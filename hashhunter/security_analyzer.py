"""Context-aware educational reports for analyzed hashes."""

from __future__ import annotations

from .hash_detector import SUPPORTED_ALGORITHMS

_WEAKNESS = {
    "md5": "Cryptographically broken and extremely fast; unsuitable for password storage.",
    "sha1": "Deprecated for collision resistance and extremely fast; unsuitable for password storage.",
    "sha224": "A fast general-purpose hash; too fast for password storage without a dedicated KDF.",
    "sha256": "A fast general-purpose hash; too fast for password storage without a dedicated KDF.",
    "sha384": "A fast general-purpose hash; too fast for password storage without a dedicated KDF.",
    "sha512": "A fast general-purpose hash; too fast for password storage without a dedicated KDF.",
    "sha3_224": "A fast general-purpose hash; too fast for password storage without a dedicated KDF.",
    "sha3_256": "A fast general-purpose hash; too fast for password storage without a dedicated KDF.",
    "sha3_384": "A fast general-purpose hash; too fast for password storage without a dedicated KDF.",
    "sha3_512": "A fast general-purpose hash; too fast for password storage without a dedicated KDF.",
    "ntlm": "Legacy unsalted MD4-based password hash; weak and unsuitable for password storage.",
    "bcrypt": "Adaptive password-hashing format; security depends on a suitable cost and unique salt.",
    "argon2": "Memory-hard password-hashing format; security depends on suitable parameters and unique salt.",
    "scrypt": "Memory-hard password-hashing format; security depends on suitable parameters and unique salt.",
    "pbkdf2_sha256": "Password-based KDF; security depends on a suitable iteration count and unique salt.",
}


def analyze_hash(algorithm: str, digest_length: int, *, format_name: str = "raw hex",
                 recovered: bool = False, candidate: str | None = None) -> dict[str, object]:
    algorithm = algorithm.lower()
    strength: str | None = None
    if recovered and candidate is not None:
        score = sum((any(c.islower() for c in candidate), any(c.isupper() for c in candidate),
                 any(c.isdigit() for c in candidate), any(not c.isalnum() for c in candidate)))
        if len(candidate) < 8:
            strength = "Very weak"
        elif len(candidate) < 12 or score < 3:
            strength = "Weak"
        elif len(candidate) >= 16 and score >= 3:
            strength = "Stronger pattern (not a security guarantee)"
        else:
            strength = "Moderate pattern (not a security guarantee)"
    return {
        "algorithm": algorithm.upper(),
        "format": format_name,
        "digest_length": digest_length,
        "digest_unit": ("hex characters" if format_name == "raw hex" else
                "encoding characters" if format_name == "bcrypt" else "bytes"),
        "weakness": _WEAKNESS.get(algorithm, "Unknown algorithm characteristics."),
        "strength_estimate": strength or "Unknown — candidate was not recovered.",
        "recommendations": [
            "For new password storage, use Argon2id with a unique cryptographically random salt and calibrated memory/time costs.",
            "bcrypt, scrypt, or PBKDF2-HMAC are alternatives when configured with appropriate work factors.",
            "Use a unique salt per password; never rely on a fast digest such as MD5 or SHA-1 for password storage.",
        ],
        "salted_format_note": "Hash format parameters and salts are taken only from supported explicit encodings or user-supplied raw-hash settings.",
    }
