"""Candidate verification for registered raw and structured hash formats."""

from __future__ import annotations

import hashlib
import hmac
import base64
import binascii
from typing import Any

import bcrypt
from argon2.low_level import Type, verify_secret
from Crypto.Hash import MD4

from .hash_detector import SUPPORTED_ALGORITHMS, normalize_algorithm, parse_hash, validate_digest


def digest_candidate(candidate: str, algorithm: str, salt: str = "", salt_position: str = "prepend") -> str:
    algorithm = normalize_algorithm(algorithm)
    if salt_position not in {"prepend", "append"}:
        raise ValueError("Salt position must be 'prepend' or 'append'.")
    if algorithm == "ntlm":
        return MD4.new(candidate.encode("utf-16le")).hexdigest()
    raw = candidate.encode("utf-8")
    salt_bytes = salt.encode("utf-8")
    payload = salt_bytes + raw if salt_position == "prepend" else raw + salt_bytes
    return hashlib.new(algorithm, payload).hexdigest()


def verify_candidate(candidate: str, digest: str, algorithm: str | None = None, salt: str = "",
                     salt_position: str = "prepend", *, format_name: str = "raw hex",
                     parameters: dict[str, Any] | None = None, encoded_hash: str | None = None) -> bool:
    """Verify one candidate; structured hashes carry their encoded parameters explicitly."""
    if format_name == "raw hex":
        if algorithm is None:
            raise ValueError("Raw digest verification requires explicit algorithm selection.")
        algorithm = normalize_algorithm(algorithm)
        if algorithm == "ntlm" and salt:
            raise ValueError("NTLM does not use a salt; clear the explicit salt setting.")
        expected = validate_digest(digest, algorithm)
        actual = digest_candidate(candidate, algorithm, salt, salt_position)
        return hmac.compare_digest(actual, expected)

    parsed = parse_hash(encoded_hash or digest)
    if not parsed.valid or not parsed.supported or not parsed.algorithm:
        raise ValueError(parsed.reason or "Unsupported hash encoding.")
    data = (parameters if parameters is not None else parsed.parameters) or {}
    encoded = encoded_hash or digest
    try:
        if parsed.format == "bcrypt":
            candidate_bytes = candidate.encode("utf-8")
            if len(candidate_bytes) > 72:
                return False
            return bcrypt.checkpw(candidate_bytes, encoded.encode("ascii"))
        if parsed.format == "argon2 PHC":
            variant = data.get("variant", "argon2id")
            kind = {"argon2id": Type.ID, "argon2i": Type.I, "argon2d": Type.D}[variant]
            return verify_secret(encoded.encode("ascii"), candidate.encode("utf-8"), kind)
        if parsed.format == "scrypt PHC subset":
            fields = encoded.split("$")
            salt_bytes = _decode64(fields[-2])
            expected = _decode64(fields[-1])
            n = 1 << int(data["log_n"])
            actual = hashlib.scrypt(candidate.encode("utf-8"), salt=salt_bytes, n=n,
                                    r=int(data["r"]), p=int(data["p"]), dklen=len(expected),
                                    maxmem=64 * 1024 * 1024)
            return hmac.compare_digest(actual, expected)
        if parsed.format == "Django PBKDF2-SHA256":
            fields = encoded.split("$")
            expected = _decode64(fields[-1])
            actual = hashlib.pbkdf2_hmac("sha256", candidate.encode("utf-8"),
                                         fields[-2].encode("utf-8"), int(data["iterations"]))
            return hmac.compare_digest(actual, expected)
    except (ValueError, KeyError, TypeError, OverflowError, MemoryError, OSError, binascii.Error):
        return False
    except Exception as exc:
        # The hash libraries signal a non-match as well as malformed values via library-specific errors.
        if exc.__class__.__module__.startswith("argon2"):
            return False
        raise
    raise ValueError("Unsupported hash encoding.")


def _decode64(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)


def supported_algorithms() -> tuple[str, ...]:
    return tuple(SUPPORTED_ALGORITHMS)
