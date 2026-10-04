"""Static analysis checks run against a parsed JWT.

Each check module exposes a `check(parsed, **options) -> list[Finding]`
function. `run_all` wires them together in a fixed order.
"""

from __future__ import annotations

from jwtlint.checks import alg_confusion, alg_none, claims, crack, header_injection, sensitive
from jwtlint.checks.base import Finding
from jwtlint.parser import ParsedToken


def run_all(
    parsed: ParsedToken,
    expect_alg: str | None = None,
    max_lifetime_seconds: int | None = None,
    crack_wordlist: list[str] | None = None,
) -> list[dict]:
    findings: list[Finding] = []

    findings.extend(alg_none.check(parsed))
    findings.extend(alg_confusion.check(parsed, expect_alg=expect_alg))
    findings.extend(header_injection.check(parsed))
    findings.extend(claims.check(parsed, max_lifetime_seconds=max_lifetime_seconds))
    findings.extend(sensitive.check(parsed))

    if crack_wordlist is not None:
        findings.extend(crack.check(parsed, wordlist=crack_wordlist))

    return [f.to_dict() for f in findings]
