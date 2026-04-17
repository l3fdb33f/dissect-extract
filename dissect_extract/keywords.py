from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from dissect_extract.util import format_record_value

# Very long alternations hurt compile time and can hit engine limits; beyond this use substring checks.
_MAX_REGEX_PATTERN_CHARS = 120_000


def parse_keyword_list_arg(s: str) -> list[str]:
    """Split a comma-separated keyword list (whitespace trimmed, empties dropped)."""

    return [part.strip() for part in s.split(",") if part.strip()]


def load_keywords_from_file(path: Path) -> list[str]:
    """Load keywords from one line per entry; ``#`` starts a comment; blank lines skipped."""

    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def merge_keywords(*batches: list[str]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for batch in batches:
        for k in batch:
            key = k.strip()
            if not key or key in seen:
                continue
            seen.add(key)
            merged.append(key)
    return merged


def _haystack(
    mapping: dict[str, Any],
    *,
    category: str,
    source_function: str,
    description: str,
) -> str:
    """Single lowercase blob for substring / regex search."""

    parts: list[str] = [
        category.lower(),
        source_function.lower(),
        description.lower(),
    ]
    for name, val in mapping.items():
        if str(name).startswith("_"):
            continue
        parts.append(format_record_value(val).lower())
    return " ".join(parts)


class KeywordFilter:
    """Case-insensitive substring match of any keyword against record text + timeline description.

    Uses one compiled regex (alternation of escaped literals) when the pattern stays small enough
    so each record is scanned once; otherwise falls back to ``any(k in haystack for k in needles)``.
    """

    __slots__ = ("_needles", "_regex")

    def __init__(self, keywords: list[str]) -> None:
        needles = merge_keywords(keywords)
        self._needles = [k.lower() for k in needles]
        self._regex: re.Pattern[str] | None = None
        if not self._needles:
            return
        escaped = [re.escape(n) for n in self._needles]
        pattern = "|".join(escaped)
        if len(pattern) <= _MAX_REGEX_PATTERN_CHARS:
            try:
                self._regex = re.compile(pattern)
            except re.error:
                self._regex = None

    @property
    def active(self) -> bool:
        return bool(self._needles)

    def matches(
        self,
        mapping: dict[str, Any],
        *,
        category: str,
        source_function: str,
        description: str,
    ) -> bool:
        if not self._needles:
            return True
        h = _haystack(
            mapping,
            category=category,
            source_function=source_function,
            description=description,
        )
        if self._regex is not None:
            return self._regex.search(h) is not None
        return any(n in h for n in self._needles)
