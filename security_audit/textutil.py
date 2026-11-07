from __future__ import annotations

import re


_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: object, limit: int = 400) -> str:
    text = _CONTROLS.sub(" ", str(value if value is not None else ""))
    text = text.replace("\r", " ").replace("\n", " ").replace("|", "/")
    return " ".join(text.split())[:limit]


def redact(text: str, patterns: list[tuple[str, re.Pattern[str]]]) -> str:
    redacted = text
    for name, pattern in patterns:
        redacted = pattern.sub(lambda _match, label=name: f"[REDACTED:{label}]", redacted)
    return redacted
