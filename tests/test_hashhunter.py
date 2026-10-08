from __future__ import annotations

import hashlib
import io
import base64
import time

import pytest
from fastapi.testclient import TestClient

from app import app, _parse_targets
from hashhunter.dictionary_engine import count_dictionary_candidates, dictionary_candidates
import bcrypt
from argon2.low_level import Type, hash_secret

from hashhunter.hash_detector import detect_hash, parse_hash
from hashhunter.hash_engine import HashTarget, candidate_stream
from hashhunter.hash_verifier import verify_candidate
from hashhunter.mask_engine import mask_candidates
from hashhunter.task_manager import Job, TaskManager
from hashhunter.wordlist_manager import iter_wordlist


@pytest.mark.parametrize("algorithm", ["md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                                        "sha3_224", "sha3_256", "sha3_384", "sha3_512"])
def test_supported_digest_verification(algorithm: str) -> None:
    password = "local-demo-password"
    digest = hashlib.new(algorithm, password.encode()).hexdigest()
    assert verify_candidate(password, digest, algorithm)
    assert not verify_candidate("wrong", digest, algorithm)


def test_invalid_digest_and_wrong_algorithm_are_rejected() -> None:
    with pytest.raises(ValueError):
        verify_candidate("password", "not-a-digest", "md5")
    with pytest.raises(ValueError):
        verify_candidate("password", "0" * 32, "sha1")
    assert not detect_hash("g" * 32).valid


def test_detector_uses_length_heuristic() -> None:
    detection = detect_hash("a" * 64)
    assert detection.valid and detection.algorithm is None
    assert set(detection.alternatives) == {"sha256", "sha3_256"}
    assert "ambiguous" in detection.note.lower()


@pytest.mark.parametrize("algorithm,digest_len", [("md5", 32), ("ntlm", 32), ("sha224", 56),
                                                   ("sha256", 64), ("sha3_224", 56),
                                                   ("sha3_256", 64), ("sha384", 96),
                                                   ("sha3_384", 96), ("sha512", 128),
                                                   ("sha3_512", 128)])
def test_explicit_algorithm_resolves_raw_digest_ambiguity(algorithm: str, digest_len: int) -> None:
    parsed = parse_hash("0" * digest_len, algorithm)
    assert parsed.valid and parsed.supported and parsed.algorithm == algorithm


def test_explicit_salt_prefix_and_suffix() -> None:
    candidate, salt = "sample", "known-salt"
    prefix = hashlib.sha256((salt + candidate).encode()).hexdigest()
    suffix = hashlib.sha256((candidate + salt).encode()).hexdigest()
    assert verify_candidate(candidate, prefix, "sha256", salt, "prepend")
    assert verify_candidate(candidate, suffix, "sha256", salt, "append")


def test_ntlm_is_utf16le_md4_and_unicode_works() -> None:
    from Crypto.Hash import MD4
    candidate = "päss🔒"
    digest = MD4.new(candidate.encode("utf-16le")).hexdigest()
    assert verify_candidate(candidate, digest, "ntlm")
    assert not verify_candidate("pass", digest, "ntlm")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def test_bcrypt_verification_and_cost_bounds() -> None:
    candidate = "Unicode-🔐"
    encoded = bcrypt.hashpw(candidate.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("ascii")
    parsed = parse_hash(encoded)
    assert parsed.supported and parsed.format == "bcrypt"
    assert parsed.salt == encoded.split("$")[3][:22]
    assert parsed.encoding == "bcrypt custom base64"
    assert verify_candidate(candidate, encoded, format_name="bcrypt")
    assert not verify_candidate("wrong", encoded, format_name="bcrypt")


def test_argon2_phc_verification() -> None:
    encoded = hash_secret(b"argon-candidate", b"eightbyte-salt", time_cost=1,
                          memory_cost=8, parallelism=1, hash_len=16, type=Type.ID).decode("ascii")
    assert verify_candidate("argon-candidate", encoded, format_name="argon2 PHC")
    assert not verify_candidate("different", encoded, format_name="argon2 PHC")


def test_scrypt_phc_subset_verification() -> None:
    salt = b"scrypt-salt"
    derived = hashlib.scrypt(b"scrypt-candidate", salt=salt, n=2**10, r=8, p=1, dklen=32)
    encoded = f"$scrypt$ln=10,r=8,p=1${_b64(salt)}${_b64(derived)}"
    assert verify_candidate("scrypt-candidate", encoded, format_name="scrypt PHC subset")
    assert not verify_candidate("wrong", encoded, format_name="scrypt PHC subset")


def test_django_pbkdf2_sha256_verification() -> None:
    salt = "django-salt"
    digest = hashlib.pbkdf2_hmac("sha256", b"django-candidate", salt.encode(), 1000)
    encoded = f"pbkdf2_sha256$1000${salt}${base64.b64encode(digest).decode()}"
    assert verify_candidate("django-candidate", encoded, format_name="Django PBKDF2-SHA256")
    assert not verify_candidate("wrong", encoded, format_name="Django PBKDF2-SHA256")


@pytest.mark.parametrize("encoded", ["$2b$xx$malformed", "$argon2id$v=19$m=bad,t=1,p=1$x$y",
                                      "$scrypt$ln=99,r=8,p=1$c2FsdA$ZGlnaWVzdA",
                                      "pbkdf2_sha256$2$salt$%%%"])
def test_malformed_or_unsafe_structured_hash_is_not_supported(encoded: str) -> None:
    parsed = parse_hash(encoded)
    assert not parsed.supported


def test_app_salted_input_is_explicit_and_prepended() -> None:
    digest = hashlib.sha256(b"saltpass").hexdigest()
    targets = _parse_targets(f"sha256$salt${digest}", None, "", "prepend")
    assert targets[0].salt == "salt"
    assert targets[0].salt_position == "prepend"
    assert targets[0].algorithm == "sha256"


def test_dictionary_candidates_and_recovery() -> None:
    digest = hashlib.sha256(b"Bluebird!1").hexdigest()
    candidates = list(dictionary_candidates("Bluebird\n", include_common=False, rules=True))
    assert "Bluebird!1" in candidates
    manager = TaskManager(max_workers=1)
    job = manager.start(candidates, [HashTarget("sha256", digest)], 15, 100)
    snapshot = wait_for_terminal(manager, job.task_id)
    assert snapshot["state"] == "completed"
    assert snapshot["progress"] == 100
    assert snapshot["matches"][0]["candidate"] == "Bluebird!1"
    assert snapshot["matches"][0]["security_report"]["strength_estimate"] != "Unknown — candidate was not recovered."


def test_dictionary_candidate_count_is_exact() -> None:
    options = {"include_common": True, "rules": True, "max_length": 16}
    candidates = list(dictionary_candidates("Bluebird\nhello\n", **options))
    assert count_dictionary_candidates("Bluebird\nhello\n", **options) == len(candidates)


def test_candidate_ceiling_completes_with_explicit_limit_status() -> None:
    consumed: list[str] = []

    def candidates():
        for value in ("one", "two", "three"):
            consumed.append(value)
            yield value

    digest = hashlib.sha256(b"not-in-list").hexdigest()
    manager = TaskManager(max_workers=1)
    job = manager.start(candidate_stream(candidates(), 2), [HashTarget("sha256", digest)], 3, 2)
    snapshot = wait_for_terminal(manager, job.task_id)
    assert snapshot["state"] == "completed"
    assert snapshot["tested_count"] == 2
    assert snapshot["limit_reached"] is True
    assert snapshot["progress"] < 100
    assert snapshot["eta_seconds"] is None
    assert consumed == ["one", "two"]


def test_mask_generation_and_ceiling() -> None:
    assert list(mask_candidates("a?d?d")) == [f"a{i}{j}" for i in "0123456789" for j in "0123456789"]
    with pytest.raises(ValueError, match="ceiling"):
        list(mask_candidates("?a?a", candidate_ceiling=10))


def test_streaming_wordlist_is_lazy_and_handles_large_sources() -> None:
    consumed: list[int] = []
    def lines():
        for index in range(100_000):
            consumed.append(index)
            yield f"candidate-{index}\n"
    stream = iter_wordlist(lines())
    assert next(stream) == "candidate-0"
    assert consumed == [0]
    assert sum(1 for _ in stream) == 99_999
    assert len(consumed) == 100_000


def test_wordlist_text_streaming_from_stringio() -> None:
    assert list(iter_wordlist(io.StringIO("first\n\nsecond\r\n"))) == ["first", "second"]


def test_task_cancel_and_pause_resume() -> None:
    manager = TaskManager(max_workers=1)
    def slow_candidates():
        for index in range(100_000):
            time.sleep(0.0002)
            yield str(index)
    digest = hashlib.md5(b"does-not-exist").hexdigest()
    job = manager.start(slow_candidates(), [HashTarget("md5", digest)], 100_000, 100_000)
    wait_until(lambda: get_job(manager, job.task_id).state == "running")
    manager.control(job.task_id, "pause")
    wait_until(lambda: get_job(manager, job.task_id).state == "paused")
    before = get_job(manager, job.task_id).snapshot()["tested_count"]
    time.sleep(0.03)
    assert get_job(manager, job.task_id).snapshot()["tested_count"] == before
    manager.control(job.task_id, "resume")
    wait_until(lambda: get_job(manager, job.task_id).snapshot()["tested_count"] > before)
    manager.control(job.task_id, "cancel")
    assert get_job(manager, job.task_id).snapshot()["state"] == "cancelled"


def test_api_requires_authorization_and_starts_local_job() -> None:
    app.state.task_manager = TaskManager(max_workers=1)
    with TestClient(app) as client:
        digest = hashlib.sha256(b"hello").hexdigest()
        denied = client.post("/api/tasks", json={"hash_text": digest, "authorized": False})
        assert denied.status_code == 422
        assert digest not in denied.text
        accepted = client.post("/api/tasks", json={"hash_text": digest, "authorized": True,
                                                        "algorithm": "sha256",
                                                    "include_common": False, "wordlist_text": "hello\n"})
        assert accepted.status_code == 200
        assert "hello" not in accepted.text
        assert accepted.json()["analysis"][0]["strength_estimate"].startswith("Unknown")
        task_id = accepted.json()["task_id"]
        result = poll_api_task(client, task_id)
        assert result["state"] == "completed"
        assert result["progress"] == 100
        assert result["matches"][0]["candidate"] == "hello"
        assert result["matches"][0]["security_report"]["strength_estimate"] == "Very weak"
        stream = client.get(f"/api/tasks/{task_id}/events")
        assert "event: progress" in stream.text and "event: done" in stream.text
        assert client.get("/api/health").json()["mode"] == "local-only"
        page = client.get("/")
        assert page.status_code == 200
        assert page.headers["cache-control"] == "no-store"
        assert page.headers["x-frame-options"] == "DENY"


def test_api_rejects_malformed_and_too_many_candidate_mask() -> None:
    app.state.task_manager = TaskManager(max_workers=1)
    with TestClient(app) as client:
        bad = client.post("/api/tasks", json={"hash_text": "z" * 32, "authorized": True})
        assert bad.status_code == 400
        huge = client.post("/api/tasks", json={"hash_text": "0" * 32, "authorized": True,
                                               "method": "mask", "mask": "?a?a?a?a?a", "candidate_ceiling": 100})
        assert huge.status_code == 400


def test_api_requires_explicit_algorithm_for_ambiguous_raw_digest() -> None:
    app.state.task_manager = TaskManager(max_workers=1)
    with TestClient(app) as client:
        rejected = client.post("/api/tasks", json={"hash_text": "0" * 32, "authorized": True})
        assert rejected.status_code == 400
        assert "ambiguous" in rejected.text.lower()
        accepted = client.post("/api/tasks", json={"hash_text": "0" * 32, "authorized": True,
                                                    "algorithm": "md5", "method": "manual",
                                                    "manual_candidate": "safe-test-candidate"})
        assert accepted.status_code == 200
        assert accepted.json()["targets"][0]["algorithm"] == "md5"


def test_csv_targets_duplicates_and_manual_candidate() -> None:
    digest = hashlib.sha256(b"csv-candidate").hexdigest()
    targets = _parse_targets(f"digest,algorithm\n{digest},sha256\n{digest},sha256\n",
                             None, "", "prepend", "csv")
    assert len(targets) == 2
    assert targets[1].duplicate_of == "Hash 1"
    app.state.task_manager = TaskManager(max_workers=1)
    with TestClient(app) as client:
        response = client.post("/api/tasks", json={"hash_text": f"digest,algorithm\n{digest},sha256\n{digest},sha256\n", "input_format": "csv",
                                                    "authorized": True, "method": "manual",
                                                    "manual_candidate": "csv-candidate"})
        assert response.status_code == 200
        snapshot = poll_api_task(client, response.json()["task_id"])
        assert snapshot["targets"][0]["status"] == "matched"
        assert snapshot["targets"][1]["status"] == "matched"
        assert len(snapshot["matches"]) == 2


def test_mixed_batch_reports_invalid_target_without_blocking_valid_match() -> None:
    digest = hashlib.sha256(b"batch-candidate").hexdigest()
    app.state.task_manager = TaskManager(max_workers=1)
    with TestClient(app) as client:
        response = client.post("/api/tasks", json={
            "hash_text": f"{digest}\nnot-a-hash", "algorithm": "sha256",
            "authorized": True, "method": "manual", "manual_candidate": "batch-candidate",
        })
        assert response.status_code == 200
        snapshot = poll_api_task(client, response.json()["task_id"])
        assert snapshot["targets"][0]["status"] == "matched"
        assert snapshot["targets"][1]["status"] == "invalid_format"
        assert len(snapshot["matches"]) == 1


def test_csv_requires_exact_digest_header() -> None:
    with pytest.raises(ValueError, match='exact column "digest"'):
        _parse_targets("hash\nabc\n", None, "", "prepend", "csv")


def test_detection_api_returns_structured_metadata_without_echoing_hash() -> None:
    encoded = hash_secret(b"api-vector", b"api-salt8", time_cost=1, memory_cost=8,
                          parallelism=1, hash_len=16, type=Type.ID).decode("ascii")
    with TestClient(app) as client:
        detected = client.post("/api/detect", json={"value": encoded})
        assert detected.status_code == 200
        payload = detected.json()
        assert payload["algorithm"] == "argon2"
        assert payload["format"] == "argon2 PHC"
        assert payload["encoding"] == "PHC base64"
        assert payload["length"] == 16
        assert payload["salt"] == "YXBpLXNhbHQ4"
        assert payload["parameters"]["time_cost"] == 1
        assert payload["confidence"] == 1.0 and payload["supported"] is True
        assert encoded not in detected.text
        ambiguous = client.post("/api/detect", json={"value": "0" * 32})
        assert ambiguous.json()["algorithm"] is None
        assert set(ambiguous.json()["alternatives"]) == {"md5", "ntlm"}


def wait_until(predicate, timeout: float = 2.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("condition did not become true")


def wait_for_terminal(manager: TaskManager, task_id: str, timeout: float = 4.0) -> dict:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = get_job(manager, task_id).snapshot()
        if result["state"] in {"completed", "cancelled", "error"}:
            return result
        time.sleep(0.005)
    raise AssertionError("task did not finish")


def poll_api_task(client: TestClient, task_id: str, timeout: float = 4.0) -> dict:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        response = client.get(f"/api/tasks/{task_id}")
        result = response.json()
        if result["state"] in {"completed", "cancelled", "error"}:
            return result
        time.sleep(0.005)
    raise AssertionError("API task did not finish")


def get_job(manager: TaskManager, task_id: str) -> Job:
    job = manager.get(task_id)
    assert job is not None
    return job
