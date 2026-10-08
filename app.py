"""HashHunter: loopback-only educational hash analysis dashboard."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator

from hashhunter.dictionary_engine import count_dictionary_candidates, dictionary_candidates
from hashhunter.hash_detector import normalize_algorithm, parse_hash
from hashhunter.hash_engine import HashTarget, candidate_stream
from hashhunter.mask_engine import estimate_mask_count, mask_candidates
from hashhunter.security_analyzer import analyze_hash
from hashhunter.task_manager import TaskManager, get_task_manager
from hashhunter.wordlist_manager import MAX_WORDLIST_BYTES, validate_wordlist_text

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
MAX_HASH_TEXT_CHARS = 512 * 1024
MAX_HASHES = 5_000
DEFAULT_CEILING = 250_000
MAX_CEILING = 1_000_000

# Intentionally avoid request-body logging: hashes, wordlists, and recovered values are sensitive.
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


class StartTaskRequest(BaseModel):
    hash_text: str = Field(min_length=1, max_length=MAX_HASH_TEXT_CHARS)
    authorized: bool
    algorithm: str | None = None
    salt: str = Field(default="", max_length=256)
    salt_position: Literal["prepend", "append"] = "prepend"
    method: Literal["dictionary", "mask", "manual"] = "dictionary"
    input_format: Literal["txt", "csv"] = "txt"
    manual_candidate: str = Field(default="", max_length=256)
    wordlist_text: str = Field(default="", max_length=MAX_WORDLIST_BYTES)
    include_common: bool = True
    apply_rules: bool = True
    max_length: int = Field(default=32, ge=1, le=64)
    mask: str = Field(default="?d?d?d?d", max_length=64)
    custom_charset: str = Field(default="", max_length=256)
    candidate_ceiling: int = Field(default=DEFAULT_CEILING, ge=1, le=MAX_CEILING)

    @field_validator("algorithm")
    @classmethod
    def valid_algorithm(cls, value: str | None) -> str | None:
        return normalize_algorithm(value) if value else None

    @model_validator(mode="after")
    def validate_inputs(self) -> "StartTaskRequest":
        if not self.authorized:
            raise ValueError("Confirm authorization before starting an analysis.")
        if len(self.wordlist_text.encode("utf-8")) > MAX_WORDLIST_BYTES:
            raise ValueError("Wordlist exceeds the 2 MiB upload limit.")
        if self.method == "mask":
            estimate_mask_count(self.mask, self.custom_charset, self.max_length)
        if self.method == "manual" and not self.manual_candidate:
            raise ValueError("Enter a non-empty manual candidate.")
        return self


class DetectHashRequest(BaseModel):
    value: str = Field(min_length=1, max_length=1024)
    algorithm: str | None = None

    @field_validator("algorithm")
    @classmethod
    def valid_algorithm(cls, value: str | None) -> str | None:
        return normalize_algorithm(value) if value else None


def _parse_targets(text: str, override_algorithm: str | None, salt: str, salt_position: str,
                   input_format: str = "txt", *, allow_invalid: bool = False) -> list[HashTarget]:
    targets: list[HashTarget] = []
    rows: list[tuple[int, str, str | None]] = []
    if input_format == "csv":
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames is None or "digest" not in reader.fieldnames:
            raise ValueError('CSV must have a header containing the exact column "digest"; optional column: "algorithm".')
        for line_number, row in enumerate(reader, start=2):
            rows.append((line_number, (row.get("digest") or "").strip(), (row.get("algorithm") or "").strip() or None))
    else:
        rows = [(line_number, line.strip(), None) for line_number, line in enumerate(text.splitlines(), start=1)]

    seen: dict[tuple[object, ...], str] = {}
    for line_number, raw, row_algorithm in rows:
        if not raw or (input_format == "txt" and raw.startswith("#")):
            continue
        label = f"Hash {len(targets) + 1}"
        try:
            target = _parse_target(raw, line_number, row_algorithm, override_algorithm, salt,
                                   salt_position, encoded_salt=None, label=label)
        except ValueError as exc:
            if not allow_invalid:
                raise
            targets.append(HashTarget(None, raw, label=label, format="invalid", encoding="unknown",
                                      digest_length=len(raw), reason="invalid format", valid=False,
                                      error=str(exc)))
            if len(targets) > MAX_HASHES:
                raise ValueError(f"A maximum of {MAX_HASHES:,} hashes can be analyzed at once.")
            continue
        fingerprint = (target.format, target.algorithm, target.digest, target.salt, target.salt_position)
        duplicate_of = seen.get(fingerprint)
        if duplicate_of is None:
            seen[fingerprint] = label
        else:
            target = replace(target, duplicate_of=duplicate_of)
        targets.append(target)
        if len(targets) > MAX_HASHES:
            raise ValueError(f"A maximum of {MAX_HASHES:,} hashes can be analyzed at once.")
    if not targets:
        raise ValueError('No hashes were found. Provide one digest per line or a CSV with a "digest" header.')
    if not any(target.valid for target in targets):
        details = "; ".join(target.error or "invalid format" for target in targets[:3])
        raise ValueError(f"No valid, supported hashes were found in the input. {details}")
    return targets


def _parse_target(raw: str, line_number: int, row_algorithm: str | None, override_algorithm: str | None,
                  salt: str, salt_position: str, *, encoded_salt: str | None, label: str) -> HashTarget:
    encoded_algorithm: str | None = None
    parse_value = raw
    if raw.count("$") == 2:
        possible_algorithm, possible_salt, possible_digest = raw.split("$", 2)
        try:
            encoded_algorithm = normalize_algorithm(possible_algorithm)
            encoded_salt, parse_value = possible_salt, possible_digest
        except ValueError:
            pass
    selected = encoded_algorithm or override_algorithm or (normalize_algorithm(row_algorithm) if row_algorithm else None)
    detection = parse_hash(parse_value, selected)
    if not detection.valid:
        raise ValueError(f"Line {line_number}: {detection.reason or detection.note}")
    if not detection.supported or detection.algorithm is None:
        alternatives = ", ".join(detection.alternatives)
        if alternatives:
            raise ValueError(f"Line {line_number}: ambiguous raw digest; select its algorithm explicitly ({alternatives}).")
        raise ValueError(f"Line {line_number}: {detection.reason or 'unsupported hash format'}")
    algorithm = detection.algorithm
    digest = parse_value.lower() if detection.format == "raw hex" else parse_value
    target_salt = ((encoded_salt if encoded_salt is not None else detection.salt or salt)
                   if detection.format == "raw hex" else (detection.salt or ""))
    target_position = "prepend" if encoded_salt is not None else salt_position
    fingerprint = (detection.format, algorithm, digest, target_salt, target_position)
    # Duplicate links are resolved in the caller after all inputs are parsed.
    return HashTarget(algorithm, digest, target_salt, target_position, label,
                      detection.format, detection.encoding, detection.parameters,
                      raw if detection.format != "raw hex" else detection.encoded_hash, None,
                      detection.digest_length, detection.confidence, detection.reason,
                      detection.alternatives)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if app.state.task_manager._closed:
        app.state.task_manager = TaskManager()
    manager = app.state.task_manager
    try:
        yield
    finally:
        manager.shutdown()


app = FastAPI(title="HashHunter", version="1.0.0", docs_url=None, redoc_url=None, lifespan=lifespan)
app.state.task_manager = get_task_manager()
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.exception_handler(RequestValidationError)
async def safe_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    # Pydantic's default payload includes rejected request values; never reflect hashes or wordlists.
    details = [{"loc": list(error.get("loc", ())), "msg": error.get("msg", "Invalid request."),
                "type": error.get("type", "value_error")} for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": details})


@app.middleware("http")
async def add_privacy_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    return response


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local-only"}


@app.post("/api/demo-hash")
def demo_hash() -> dict[str, str]:
    """Create a harmless demo digest in memory for learning and UI testing."""
    sample = "password"
    return {"algorithm": "sha256", "hash": hashlib.sha256(sample.encode("utf-8")).hexdigest(),
            "message": "A demo digest was generated locally from the built-in training sample."}


@app.post("/api/detect")
def inspect_hash(request: DetectHashRequest) -> dict[str, object]:
    """Return parser metadata without retaining or echoing the supplied hash."""
    detection = parse_hash(request.value, request.algorithm)
    return {"algorithm": detection.algorithm, "format": detection.format,
            "encoding": detection.encoding, "length": detection.digest_length,
            "salt": detection.salt, "parameters": detection.parameters,
            "confidence": detection.confidence, "reason": detection.reason,
            "note": detection.note, "alternatives": list(detection.alternatives),
            "valid": detection.valid, "supported": detection.supported}


@app.post("/api/tasks")
def start_task(request: StartTaskRequest) -> dict[str, object]:
    manager: TaskManager = app.state.task_manager
    try:
        targets = _parse_targets(request.hash_text, request.algorithm, request.salt,
                                 request.salt_position, request.input_format, allow_invalid=True)
        effective_ceiling = request.candidate_ceiling
        valid_targets = [target for target in targets if target.valid]
        if request.method != "manual" and any(target.format != "raw hex" for target in valid_targets):
            effective_ceiling = min(effective_ceiling, 100)
        if request.method == "dictionary":
            validate_wordlist_text(request.wordlist_text)
            total = count_dictionary_candidates(request.wordlist_text, include_common=request.include_common,
                                                rules=request.apply_rules, max_length=request.max_length)
            candidates = dictionary_candidates(request.wordlist_text, include_common=request.include_common,
                                               rules=request.apply_rules, max_length=request.max_length)
        elif request.method == "mask":
            total = estimate_mask_count(request.mask, request.custom_charset, request.max_length)
            if total > request.candidate_ceiling:
                raise ValueError(f"Mask generates {total:,} candidates, above the {request.candidate_ceiling:,} candidate ceiling.")
            candidates = mask_candidates(request.mask, request.custom_charset, request.max_length, request.candidate_ceiling)
        else:
            total = 1
            candidates = iter((request.manual_candidate,))
        job = manager.start(candidate_stream(candidates, effective_ceiling), targets, total, effective_ceiling)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"task_id": job.task_id, "state": job.state,
            "analysis": [analyze_hash(t.algorithm or "unknown", t.digest_length or len(t.digest),
                                      format_name=t.format, recovered=False) for t in targets if t.valid],
            "targets": [{"target": t.label, "algorithm": t.algorithm or "unknown", "format": t.format,
                         "encoding": t.encoding, "length": t.digest_length, "salt": t.salt,
                         "parameters": t.parameters, "confidence": t.confidence,
                         "reason": t.reason, "alternatives": list(t.alternatives),
                         "duplicate_of": t.duplicate_of,
                         "status": "pending" if t.valid else "invalid_format",
                         "error": t.error} for t in targets],
            "effective_candidate_ceiling": effective_ceiling}


@app.get("/api/tasks/{task_id}")
def get_task(task_id: str) -> dict[str, object]:
    job = app.state.task_manager.get(task_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Task not found.")
    snapshot = job.snapshot()
    return snapshot


@app.post("/api/tasks/{task_id}/{action}")
def control_task(task_id: str, action: Literal["pause", "resume", "cancel"]) -> dict[str, object]:
    try:
        return app.state.task_manager.control(task_id, action).snapshot()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/tasks/{task_id}/events")
async def task_events(task_id: str) -> StreamingResponse:
    if app.state.task_manager.get(task_id) is None:
        raise HTTPException(status_code=404, detail="Task not found.")

    async def events() -> AsyncIterator[str]:
        last_payload = ""
        while True:
            job = app.state.task_manager.get(task_id)
            if job is None:
                yield "event: error\ndata: {\"error\":\"Task not found.\"}\n\n"
                break
            payload = json.dumps(job.snapshot(), separators=(",", ":"))
            if payload != last_payload:
                yield f"event: progress\ndata: {payload}\n\n"
                last_payload = payload
            if job.state in {"completed", "cancelled", "error"}:
                yield "event: done\ndata: {}\n\n"
                break
            await asyncio.sleep(0.35)

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False, access_log=False)
