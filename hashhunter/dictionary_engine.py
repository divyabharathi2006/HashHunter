"""Streaming dictionary candidates and small, explicit transformation rules."""

from __future__ import annotations

from collections.abc import Iterator

from .wordlist_manager import iter_wordlist

COMMON_PASSWORDS = (
    "password", "123456", "password1", "123456789", "qwerty", "letmein",
    "welcome", "admin", "iloveyou", "monkey", "dragon", "abc123",
    "sunshine", "football", "master", "hello", "changeme", "trustno1",
)


def transform_word(word: str, *, rules: bool = True, max_length: int = 64) -> Iterator[str]:
    """Yield the original and bounded, deterministic common transformations."""
    seen: set[str] = set()
    variants = [word]
    if rules:
        variants.extend((word.lower(), word.upper(), word.capitalize(), word[::-1]))
        variants.extend(word + suffix for suffix in ("1", "123", "!", "!1", "2024", "2025", "2026"))
        variants.extend(word.replace(a, b) for a, b in (("a", "@"), ("e", "3"), ("i", "1"), ("o", "0")))
    for value in variants:
        if value and len(value) <= max_length and value not in seen:
            seen.add(value)
            yield value


def dictionary_candidates(wordlist_text: str = "", *, include_common: bool = True, rules: bool = True,
                          max_length: int = 64) -> Iterator[str]:
    if include_common:
        for word in COMMON_PASSWORDS:
            yield from transform_word(word, rules=rules, max_length=max_length)
    for word in iter_wordlist(wordlist_text):
        yield from transform_word(word, rules=rules, max_length=max_length)


def count_dictionary_candidates(wordlist_text: str = "", *, include_common: bool = True, rules: bool = True,
                                 max_length: int = 64) -> int:
    """Count the exact streamed candidate sequence without retaining it in memory."""
    return sum(1 for _ in dictionary_candidates(wordlist_text, include_common=include_common,
                                                rules=rules, max_length=max_length))
