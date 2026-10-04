"""Sensitive data in the payload.

A JWS payload is base64url, not encryption. Anyone holding the token (logs,
browser storage, proxies, referer headers) can read it. Flag claim names and
values that look like they shouldn't be there.
"""

from __future__ import annotations

import re
from typing import Any

from jwtlint.checks.base import Finding
from jwtlint.parser import ParsedToken

CHECK_NAME = "sensitive-data"

# Matched against the claim name normalised to snake_case, on word edges, so
# "shipping" doesn't hit "pin" and "token_type" doesn't hit "token".
_SECRET_KEYS = re.compile(
    r"(^|_)(pass|password|passwd|pwd|secret|api_?key|private_?key|access_?key|"
    r"client_?secret|access_?token|refresh_?token|id_?token|session_?id|otp|pin|cvv)(_|$)"
)
_PII_KEYS = re.compile(
    r"(^|_)(ssn|social_?security|tc_?kimlik|tckn|national_?id|passport|"
    r"iban|card_?number|credit_?card|dob|birth_?date|date_?of_?birth|phone|phone_?number|address)(_|$)"
)

_VALUE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("card number", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
]


def check(parsed: ParsedToken) -> list[Finding]:
    findings: list[Finding] = []
    for path, raw_key, value in _walk(parsed.payload):
        key = _snake(raw_key)
        if _SECRET_KEYS.search(key) and _has_content(value):
            findings.append(_finding(path, "secret-looking claim", "high"))
        elif _PII_KEYS.search(key) and _has_content(value):
            findings.append(_finding(path, "personal data claim", "medium"))
        elif isinstance(value, str):
            for label, pattern in _VALUE_PATTERNS:
                if pattern.search(value) and (label != "card number" or _luhn(value)):
                    findings.append(_finding(path, f"{label} in claim value", "high"))
                    break
    return findings


def _finding(path: str, what: str, severity: str) -> Finding:
    return Finding(
        check=CHECK_NAME,
        title=f"{what}: {path}",
        description=(
            f"Claim {path!r} looks sensitive. JWT payloads are only base64url "
            "encoded, so anyone who sees the token can read it. Keep secrets "
            "and personal data server-side, or use an encrypted JWE."
        ),
        severity=severity,
        evidence={"claim": path},
    )


def _walk(obj: Any, prefix: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            yield path, str(k), v
            yield from _walk(v, path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{prefix}[{i}]")


def _snake(key: str) -> str:
    key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    return re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")


def _has_content(value: Any) -> bool:
    if isinstance(value, (dict, list)):
        return False
    return value not in (None, "", False)


def _luhn(text: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", text)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
