"""Candidate iteration and match checks, isolated from HTTP and presentation."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any
from itertools import islice

from .hash_verifier import verify_candidate


@dataclass(frozen=True)
class HashTarget:
    algorithm: str | None
    digest: str
    salt: str = ""
    salt_position: str = "prepend"
    label: str = "Hash"
    format: str = "raw hex"
    encoding: str = "hex"
    parameters: dict[str, Any] | None = None
    encoded_hash: str | None = None
    duplicate_of: str | None = None
    digest_length: int | None = None
    confidence: float = 0.0
    reason: str = ""
    alternatives: tuple[str, ...] = ()
    valid: bool = True
    error: str | None = None


def first_match(candidate: str, targets: Sequence[HashTarget]) -> list[int]:
    """Return indexes of matching targets; plaintext is returned only for a match."""
    return [index for index, target in enumerate(targets)
            if target.valid and target.algorithm is not None and
            verify_candidate(candidate, target.digest, target.algorithm, target.salt, target.salt_position,
                                format_name=target.format, parameters=target.parameters,
                                encoded_hash=target.encoded_hash)]


def candidate_stream(candidates: Iterable[str], ceiling: int) -> Iterator[str]:
    if ceiling < 0:
        raise ValueError("Candidate ceiling cannot be negative.")
    yield from islice(candidates, ceiling)
