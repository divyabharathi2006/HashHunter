"""Volatile background jobs with bounded workers and cooperative controls."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .hash_engine import HashTarget, first_match
from .security_analyzer import analyze_hash


@dataclass
class Job:
    task_id: str
    total_candidates: int | None
    state: str = "queued"
    tested_count: int = 0
    matches: list[dict[str, Any]] = field(default_factory=list)
    target_statuses: list[dict[str, str | None]] = field(default_factory=list)
    error: str | None = None
    limit_reached: bool = False
    started_at: float | None = None
    updated_at: float = field(default_factory=time.monotonic)
    rate: float = 0.0
    _condition: threading.Condition = field(default_factory=threading.Condition, repr=False)

    def snapshot(self) -> dict[str, Any]:
        with self._condition:
            elapsed = max(0.001, time.monotonic() - (self.started_at or time.monotonic()))
            remaining = max(0, self.total_candidates - self.tested_count) if self.total_candidates is not None else None
            active = self.state in {"queued", "running", "paused"}
            eta = remaining / self.rate if active and remaining is not None and self.rate > 0 else None
            progress = (100.0 if self.state == "completed" and not self.limit_reached else
                        min(100.0, self.tested_count / self.total_candidates * 100) if self.total_candidates else 0.0)
            return {
                "task_id": self.task_id, "state": self.state, "progress": round(progress, 2),
                "rate": round(self.rate, 2), "tested_count": self.tested_count,
                "total_candidates": self.total_candidates, "eta_seconds": round(eta, 1) if eta is not None else None,
                "matches": [dict(match) for match in self.matches], "error": self.error,
                "targets": [dict(target) for target in self.target_statuses],
                "limit_reached": self.limit_reached,
                "elapsed_seconds": round(elapsed, 1),
            }


class TaskManager:
    def __init__(self, max_workers: int = 2, max_jobs: int = 16):
        self._executor = ThreadPoolExecutor(max_workers=min(max(1, max_workers), 2), thread_name_prefix="hashhunter")
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._max_jobs = max_jobs
        self._closed = False

    def start(self, candidates: Iterable[str], targets: Sequence[HashTarget], total_candidates: int | None,
              candidate_ceiling: int) -> Job:
        with self._lock:
            self._prune()
            if len(self._jobs) >= self._max_jobs:
                raise ValueError("Too many retained tasks; wait for older tasks to finish and try again.")
            job = Job(str(uuid.uuid4()), total_candidates,
                      limit_reached=total_candidates is not None and total_candidates > candidate_ceiling,
                      target_statuses=[{"target": target.label, "algorithm": target.algorithm or "unknown",
                                        "format": target.format,
                                        "status": "pending" if target.valid else "invalid_format",
                                        "duplicate_of": target.duplicate_of,
                                        "reason": target.error or target.reason} for target in targets])
            self._jobs[job.task_id] = job
        try:
            self._executor.submit(self._run, job, candidates, tuple(targets), candidate_ceiling)
        except RuntimeError as exc:
            with self._lock:
                self._jobs.pop(job.task_id, None)
            raise ValueError("The local task manager is shutting down; restart the app and retry.") from exc
        return job

    def get(self, task_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(task_id)

    def control(self, task_id: str, action: str) -> Job:
        job = self.get(task_id)
        if job is None:
            raise KeyError("Task not found.")
        with job._condition:
            if action == "pause" and job.state == "running":
                job.state = "paused"
            elif action == "resume" and job.state == "paused":
                job.state = "running"
                job._condition.notify_all()
            elif action == "cancel" and job.state in {"queued", "running", "paused"}:
                job.state = "cancelled"
                for status in job.target_statuses:
                    if status["status"] == "pending":
                        status["status"] = "cancelled"
                job._condition.notify_all()
            else:
                raise ValueError(f"Cannot {action} a task in the {job.state} state.")
            job.updated_at = time.monotonic()
        return job

    def _run(self, job: Job, candidates: Iterable[str], targets: Sequence[HashTarget], ceiling: int) -> None:
        with job._condition:
            if job.state == "cancelled":
                return
            job.state = "running"
            job.started_at = time.monotonic()
            job._condition.notify_all()
        last_update = time.monotonic()
        try:
            for candidate in candidates:
                with job._condition:
                    while job.state == "paused":
                        job._condition.wait(timeout=0.5)
                    if job.state == "cancelled":
                        return
                    if job.tested_count >= ceiling:
                        job.limit_reached = True
                        for status in job.target_statuses:
                            if status["status"] == "pending":
                                status["status"] = "not_tested_limit"
                        job.state = "completed"
                        job.updated_at = time.monotonic()
                        job._condition.notify_all()
                        return
                matched = first_match(candidate, targets)
                now = time.monotonic()
                with job._condition:
                    job.tested_count += 1
                    for index in matched:
                        job.target_statuses[index]["status"] = "matched"
                        # Only retain plaintext for a confirmed matching digest.
                        job.matches.append({"target": targets[index].label, "candidate": candidate,
                                            "algorithm": (targets[index].algorithm or "unknown").upper(),
                                            "format": targets[index].format,
                                            "security_report": analyze_hash(targets[index].algorithm or "unknown",
                                                                            targets[index].digest_length or len(targets[index].digest),
                                                                            format_name=targets[index].format,
                                                                            recovered=True,
                                                                            candidate=candidate)})
                    elapsed = max(0.001, now - (job.started_at or now))
                    job.rate = job.tested_count / elapsed
                    if now - last_update >= 0.2:
                        job.updated_at = now
                        last_update = now
                    job._condition.notify_all()
            with job._condition:
                if job.state != "cancelled":
                    for status in job.target_statuses:
                        if status["status"] == "pending":
                            status["status"] = ("not_tested_limit" if job.limit_reached and
                                                 job.total_candidates is not None and
                                                 job.tested_count < job.total_candidates else "not_matched")
                    job.state = "completed"
                    job.updated_at = time.monotonic()
                    job._condition.notify_all()
        except Exception:
            # Do not include exception strings: input content must never leak into errors/logs.
            with job._condition:
                job.error = "The job stopped because its candidate source could not be processed. Check the settings and input limits."
                for status in job.target_statuses:
                    if status["status"] == "pending":
                        status["status"] = "error"
                job.state = "error"
                job.updated_at = time.monotonic()
                job._condition.notify_all()

    def _prune(self) -> None:
        terminal = {"completed", "cancelled", "error"}
        for task_id, job in list(self._jobs.items()):
            if len(self._jobs) < self._max_jobs:
                break
            if job.state in terminal:
                self._jobs.pop(task_id, None)

    def shutdown(self) -> None:
        """Cancel active work and stop worker threads during app shutdown."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            jobs = list(self._jobs.values())
        for job in jobs:
            with job._condition:
                if job.state in {"queued", "running", "paused"}:
                    job.state = "cancelled"
                    for status in job.target_statuses:
                        if status["status"] == "pending":
                            status["status"] = "cancelled"
                    job._condition.notify_all()
        self._executor.shutdown(wait=True, cancel_futures=True)


_default_manager: TaskManager | None = None
_default_lock = threading.Lock()


def get_task_manager() -> TaskManager:
    global _default_manager
    with _default_lock:
        if _default_manager is None or _default_manager._closed:
            _default_manager = TaskManager()
        return _default_manager
