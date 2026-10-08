"""Bounded mask candidate generation without materializing the candidate space."""

from __future__ import annotations

import itertools
import math
from collections.abc import Iterator, Sequence

CHARSETS = {
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits": "0123456789",
    "symbols": "!@#$%^&*()-_=+[]{};:,.?",
    "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
}
_MASK_TOKENS = {"?l": CHARSETS["lower"], "?u": CHARSETS["upper"], "?d": CHARSETS["digits"],
                "?s": CHARSETS["symbols"], "?a": CHARSETS["alnum"]}


def parse_mask(mask: str, custom_charset: str = "") -> list[str]:
    """Parse literals and tokens ?l/?u/?d/?s/?a; ?c uses the supplied charset."""
    charsets: list[str] = []
    i = 0
    while i < len(mask):
        if mask[i] == "?":
            token = mask[i:i + 2]
            if token == "?c":
                charset = custom_charset
            else:
                charset = _MASK_TOKENS.get(token, "")
            if not charset:
                raise ValueError(f"Unknown or empty mask token: {token}")
            charsets.append("".join(dict.fromkeys(charset)))
            i += 2
        else:
            charsets.append(mask[i])
            i += 1
    if not charsets:
        raise ValueError("Provide a mask such as ?l?d?d or a literal value.")
    return charsets


def estimate_mask_count(mask: str, custom_charset: str = "", max_length: int = 64) -> int:
    charsets = parse_mask(mask, custom_charset)
    if len(charsets) > max_length:
        raise ValueError("Mask length exceeds the configured maximum.")
    return math.prod(len(charset) for charset in charsets)


def mask_candidates(mask: str, custom_charset: str = "", max_length: int = 64,
                    candidate_ceiling: int = 1_000_000) -> Iterator[str]:
    charsets = parse_mask(mask, custom_charset)
    if len(charsets) > max_length:
        raise ValueError("Mask length exceeds the configured maximum.")
    total = math.prod(len(charset) for charset in charsets)
    if total > candidate_ceiling:
        raise ValueError(f"Mask generates {total:,} candidates, above the {candidate_ceiling:,} candidate ceiling.")
    for chars in itertools.product(*charsets):
        yield "".join(chars)


def charset_mask(charset_names: Sequence[str], max_length: int, candidate_ceiling: int = 1_000_000) -> Iterator[str]:
    """Generate 1..max_length strings for selected named charsets, within the ceiling."""
    if not charset_names or max_length < 1:
        raise ValueError("Choose at least one charset and a positive maximum length.")
    try:
        charset = "".join(dict.fromkeys("".join(CHARSETS[name] for name in charset_names)))
    except KeyError as exc:
        raise ValueError(f"Unknown charset: {exc.args[0]}") from exc
    total = sum(len(charset) ** length for length in range(1, max_length + 1))
    if total > candidate_ceiling:
        raise ValueError(f"Configuration generates {total:,} candidates, above the {candidate_ceiling:,} candidate ceiling.")
    for length in range(1, max_length + 1):
        for chars in itertools.product(charset, repeat=length):
            yield "".join(chars)
