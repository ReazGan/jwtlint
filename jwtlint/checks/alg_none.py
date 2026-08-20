"""`alg: none` check (CVE-class: JWT algorithm-none forgery).

Some JWT libraries historically honored `"alg": "none"` (or accepted it
case-insensitively — `"None"`, `"NONE"`, `"nOnE"`) and skipped signature
verification entirely. An attacker who can set the header can then forge
any payload with an empty signature segment. This is check #1 in basically
every JWT security write-up because it's still found in the wild in custom
or misconfigured verifiers.
"""

from __future__ import annotations

from jwtlint.checks.base import Finding
from jwtlint.parser import ParsedToken

CHECK_NAME = "alg-none"


def check(parsed: ParsedToken) -> list[Finding]:
    alg = parsed.header.get("alg")
    if not isinstance(alg, str):
        return []

    if alg.lower() != "none":
        return []

    findings = [
        Finding(
            check=CHECK_NAME,
            title=f"alg: {alg!r} — unsigned/forgeable token",
            description=(
                "The header sets alg to a case-variant of 'none'. Libraries that "
                "compare this case-insensitively (or that special-case 'none' "
                "without validating the signature segment) will accept this token "
                "with any payload and no valid signature — a classic auth bypass. "
                "A safe verifier must reject 'none' outright and only accept an "
                "algorithm it was explicitly configured to expect."
            ),
            severity="critical",
            evidence={"alg": alg},
        )
    ]

    if parsed.signature_segment.strip():
        findings.append(
            Finding(
                check=CHECK_NAME,
                title="alg: none token carries a non-empty signature segment",
                description=(
                    "alg is 'none' but the signature segment is non-empty. This is "
                    "unusual — a spec-compliant 'none' token has an empty third "
                    "segment. The signature bytes present here are ignored by any "
                    "verifier that honors alg: none, so they provide no protection."
                ),
                severity="low",
                evidence={"alg": alg, "signature_segment_length": len(parsed.signature_segment)},
            )
        )

    return findings
