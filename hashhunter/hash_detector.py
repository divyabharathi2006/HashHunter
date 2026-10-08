"""Registry and parser for supported raw digests and structured password hashes."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any

SUPPORTED_ALGORITHMS: dict[str, int] = {
    "md5": 32,
    "sha1": 40,
    "sha224": 56,
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
    "sha3_224": 56,
    "sha3_256": 64,
    "sha3_384": 96,
    "sha3_512": 128,
    "ntlm": 32,
}
_ALIASES = {
    "sha-1": "sha1", "sha-224": "sha224", "sha-256": "sha256",
    "sha-384": "sha384", "sha-512": "sha512", "sha3-224": "sha3_224",
    "sha3-256": "sha3_256", "sha3-384": "sha3_384", "sha3-512": "sha3_512",
    "sha3_224": "sha3_224", "sha3_256": "sha3_256", "sha3_384": "sha3_384",
    "sha3_512": "sha3_512", "ntlm": "ntlm",
}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_BCRYPT = re.compile(r"^\$(2[aby])\$(\d{2})\$([./A-Za-z0-9]{53})$")
_ARGON = re.compile(r"^\$(argon2id|argon2i|argon2d)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$")
_SCRYPT = re.compile(r"^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$")
_DJANGO_PBKDF2 = re.compile(r"^pbkdf2_sha256\$(\d+)\$([^$]+)\$([A-Za-z0-9+/]+={0,2})$")


@dataclass(frozen=True)
class Detection:
    algorithm: str | None
    confidence: float
    digest_length: int
    valid: bool
    note: str
    format: str = "unknown"
    encoding: str = "unknown"
    salt: str | None = None
    parameters: dict[str, Any] | None = None
    reason: str = ""
    alternatives: tuple[str, ...] = ()
    supported: bool = False
    encoded_hash: str | None = None


def normalize_algorithm(algorithm: str) -> str:
    normalized = algorithm.strip().lower()
    normalized = _ALIASES.get(normalized, normalized)
    if normalized not in SUPPORTED_ALGORITHMS:
        raise ValueError("Select one of the supported raw digest algorithms or NTLM explicitly.")
    return normalized


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)


def parse_hash(value: str, explicit_algorithm: str | None = None) -> Detection:
    """Parse supported formats; raw hex is ambiguous unless explicitly selected."""
    value = value.strip()
    length = len(value)
    if not value:
        return Detection(None, 0.0, length, False, "Enter a hash value.", reason="empty input")

    bcrypt = _BCRYPT.fullmatch(value)
    if bcrypt:
        cost = int(bcrypt.group(2))
        supported = 4 <= cost <= 12
        salt = bcrypt.group(3)[:22]
        return Detection("bcrypt", 1.0, 60, True, "Recognized bcrypt modular crypt encoding.",
                         "bcrypt", "bcrypt custom base64", salt, {"variant": bcrypt.group(1), "cost": cost},
                         "Verified with bcrypt; cost above 12 is refused to bound local work." if not supported else "Recognized bcrypt variant and cost.",
                         (), supported, value)
    argon = _ARGON.fullmatch(value)
    if argon:
        variant, version, memory, time_cost, parallelism, salt_b64, digest_b64 = argon.groups()
        try:
            salt_bytes, digest_bytes = _b64decode(salt_b64), _b64decode(digest_b64)
        except (ValueError, binascii.Error):
            return Detection(None, 0.0, length, False, "Malformed Argon2 PHC base64 field.", "argon2 PHC", "PHC base64", reason="invalid base64")
        params = {"variant": variant, "version": int(version), "memory_cost": int(memory),
                  "time_cost": int(time_cost), "parallelism": int(parallelism)}
        supported = (int(version) == 19 and 8 <= len(salt_bytes) <= 64 and 16 <= len(digest_bytes) <= 64
                     and 8 <= int(memory) <= 32768 and 1 <= int(time_cost) <= 3
                     and 1 <= int(parallelism) <= 8 and int(memory) >= 8 * int(parallelism))
        reason = "Argon2 parameters exceed the local safety limits or unsupported PHC version." if not supported else "Recognized Argon2 PHC encoding."
        return Detection("argon2", 1.0, len(digest_bytes), True, reason, "argon2 PHC", "PHC base64",
                         salt_b64, params, reason, (), supported, value)
    scrypt = _SCRYPT.fullmatch(value)
    if scrypt:
        log_n, r, p, salt_b64, digest_b64 = scrypt.groups()
        try:
            salt_bytes, digest_bytes = _b64decode(salt_b64), _b64decode(digest_b64)
        except (ValueError, binascii.Error):
            return Detection(None, 0.0, length, False, "Malformed scrypt PHC base64 field.", "scrypt PHC", "PHC base64", reason="invalid base64")
        params = {"log_n": int(log_n), "r": int(r), "p": int(p)}
        supported = (10 <= int(log_n) <= 20 and 1 <= int(r) <= 16 and 1 <= int(p) <= 8
                     and 8 <= len(salt_bytes) <= 64 and 16 <= len(digest_bytes) <= 64)
        supported = supported and 128 * (1 << int(log_n)) * int(r) <= 32 * 1024 * 1024
        reason = "scrypt parameters exceed local safety limits." if not supported else "Recognized HashHunter scrypt PHC subset."
        return Detection("scrypt", 1.0, len(digest_bytes), True, reason, "scrypt PHC subset", "PHC base64",
                         salt_b64, params, reason, (), supported, value)
    django = _DJANGO_PBKDF2.fullmatch(value)
    if django:
        iterations, salt, checksum = django.groups()
        try:
            digest_bytes = _b64decode(checksum)
        except (ValueError, binascii.Error):
            return Detection(None, 0.0, length, False, "Malformed Django PBKDF2 base64 digest.", "Django PBKDF2-SHA256", "base64", reason="invalid base64")
        params = {"iterations": int(iterations)}
        supported = 1 <= int(iterations) <= 500_000 and len(digest_bytes) == 32
        reason = "PBKDF2 iteration count or digest size is outside local safety limits." if not supported else "Recognized Django PBKDF2-SHA256 encoding."
        return Detection("pbkdf2_sha256", 1.0, len(digest_bytes), True, reason, "Django PBKDF2-SHA256", "base64",
                         salt, params, reason, (), supported, value)

    # Unsupported modular crypt and PHC variants are recognized, never silently reinterpreted.
    if value.startswith(("$2", "$argon2", "$scrypt$", "$pbkdf2-", "$1$", "$5$", "$6$")):
        return Detection(None, 1.0, length, True, "Recognized encoded-hash family, but this exact variant is not supported.",
                         "unsupported modular/PHC", "encoded", reason="unsupported format variant", supported=False, encoded_hash=value)

    if not _HEX.fullmatch(value):
        return Detection(None, 0.0, length, False, "Not a recognized supported encoding or hexadecimal digest.",
                         reason="malformed or unsupported encoding")
    candidates = tuple(name for name, size in SUPPORTED_ALGORITHMS.items() if size == length)
    if explicit_algorithm:
        try:
            algorithm = normalize_algorithm(explicit_algorithm)
        except ValueError as exc:
            return Detection(None, 0.0, length, False, str(exc), format="raw hex", encoding="hex", reason="unknown algorithm")
        if SUPPORTED_ALGORITHMS[algorithm] != length:
            return Detection(None, 0.0, length, False, f"Length does not match explicitly selected {algorithm.upper()}.",
                             "raw hex", "hex", reason="algorithm/length mismatch")
        return Detection(algorithm, 1.0, length, True, f"Explicitly selected {algorithm.upper()} raw hexadecimal digest.",
                         "raw hex", "hex", None, {}, "algorithm chosen manually; length is not proof", (), True, value)
    if not candidates:
        return Detection(None, 0.0, length, False, "Hexadecimal digest length does not match a supported algorithm.",
                         "raw hex", "hex", reason="unsupported digest length")
    if len(candidates) > 1:
        pretty = ", ".join(name.upper().replace("_", "-") for name in candidates)
        return Detection(None, 0.0, length, True, f"Ambiguous {length}-character raw digest ({pretty}); select the algorithm manually.",
                         "raw hex", "hex", reason="multiple supported algorithms share this length", alternatives=candidates,
                         supported=True, encoded_hash=value)
    algorithm = candidates[0]
    return Detection(algorithm, 0.82, length, True,
                     "Likely raw digest based on length only; confirm the algorithm if known.",
                     "raw hex", "hex", reason="length-based heuristic, not proof", alternatives=candidates,
                     supported=True, encoded_hash=value)


def detect_hash(value: str, explicit_algorithm: str | None = None) -> Detection:
    """Compatibility entry point for parser-backed detection."""
    return parse_hash(value, explicit_algorithm)


def validate_digest(digest: str, algorithm: str) -> str:
    algorithm = normalize_algorithm(algorithm)
    digest = digest.strip().lower()
    if len(digest) != SUPPORTED_ALGORITHMS[algorithm] or not _HEX.fullmatch(digest):
        raise ValueError(f"Digest is not a valid {algorithm.upper()} hexadecimal value.")
    return digest
