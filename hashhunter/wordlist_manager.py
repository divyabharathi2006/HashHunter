"""Bounded, streaming wordlist helpers. No uploaded wordlist is written to disk."""

from __future__ import annotations

import io
from collections.abc import Iterable, Iterator
from typing import TextIO

MAX_WORDLIST_BYTES = 2 * 1024 * 1024
MAX_WORDLIST_LINES = 250_000


def iter_wordlist(source: str | TextIO | Iterable[str], *, max_lines: int = MAX_WORDLIST_LINES) -> Iterator[str]:
    """Yield normalized non-empty candidates one line at a time."""
    stream: Iterable[str]
    if isinstance(source, str):
        stream = io.StringIO(source)
    else:
        stream = source
    for index, line in enumerate(stream, start=1):
        if index > max_lines:
            raise ValueError(f"Wordlist exceeds the {max_lines:,}-line limit.")
        word = line.rstrip("\r\n")
        if word:
            yield word


def validate_wordlist_text(text: str) -> str:
    if len(text.encode("utf-8")) > MAX_WORDLIST_BYTES:
        raise ValueError(f"Wordlist exceeds the {MAX_WORDLIST_BYTES // (1024 * 1024)} MiB upload limit.")
    # Count incrementally; do not split the entire upload into a second list.
    lines = sum(1 for _ in io.StringIO(text))
    if lines > MAX_WORDLIST_LINES:
        raise ValueError(f"Wordlist exceeds the {MAX_WORDLIST_LINES:,}-line limit.")
    return text
