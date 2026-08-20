"""Standard claim hygiene checks (RFC 7519 section 4.1).

Covers: missing exp, already-expired exp (informational), missing iat, nbf
that looks wrong relative to iat, and unreasonably long-lived tokens.
"""

from __future__ import annotations

import time

from jwtlint.checks.base import Finding
from jwtlint.parser import ParsedToken

CHECK_NAME = "claims"

# A year, as a round default for "this token lives suspiciously long."
DEFAULT_MAX_LIFETIME_SECONDS = 365 * 24 * 3600


def _numeric_claim(payload: dict, name: str) -> float | None:
    value = payload.get(name)
    if isinstance(value, bool):  # bool is a subclass of int, exclude explicitly
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def check(parsed: ParsedToken, max_lifetime_seconds: int | None = None) -> list[Finding]:
    threshold = max_lifetime_seconds if max_lifetime_seconds is not None else DEFAULT_MAX_LIFETIME_SECONDS
    payload = parsed.payload
    findings: list[Finding] = []
    now = time.time()

    exp = _numeric_claim(payload, "exp")
    iat = _numeric_claim(payload, "iat")
    nbf = _numeric_claim(payload, "nbf")

    if "exp" not in payload:
        findings.append(
            Finding(
                check=CHECK_NAME,
                title="No exp (expiration) claim",
                description=(
                    "The token has no exp claim, so it never expires by "
                    "definition. A stolen or leaked token remains valid "
                    "indefinitely unless revoked out-of-band. Every token "
                    "issued to a client should carry a bounded expiration."
                ),
                severity="high",
                evidence={},
            )
        )
    elif exp is None:
        findings.append(
            Finding(
                check=CHECK_NAME,
                title="exp claim is not a valid NumericDate",
                description=(
                    "exp is present but is not a number (RFC 7519 requires exp to "
                    "be a NumericDate — seconds since the Unix epoch). A verifier "
                    "that fails to validate this type may treat the token as "
                    "never expiring."
                ),
                severity="medium",
                evidence={"exp": payload.get("exp")},
            )
        )
    elif exp < now:
        findings.append(
            Finding(
                check=CHECK_NAME,
                title="Token is expired",
                description=(
                    f"exp ({exp:.0f}) is in the past relative to the current time "
                    f"({now:.0f}). This isn't a vulnerability by itself — an "
                    "expired token should be rejected by any correct verifier — "
                    "it's just noted for context."
                ),
                severity="info",
                evidence={"exp": exp, "now": now, "expired_seconds_ago": now - exp},
            )
        )

    if "iat" not in payload:
        findings.append(
            Finding(
                check=CHECK_NAME,
                title="No iat (issued-at) claim",
                description=(
                    "The token has no iat claim. iat isn't required by the spec, "
                    "but without it there's no record of when the token was "
                    "issued, which makes it harder to reason about token age, "
                    "detect replay of very old tokens, or audit issuance."
                ),
                severity="low",
                evidence={},
            )
        )
    elif iat is None:
        findings.append(
            Finding(
                check=CHECK_NAME,
                title="iat claim is not a valid NumericDate",
                description="iat is present but is not a number (RFC 7519 NumericDate).",
                severity="low",
                evidence={"iat": payload.get("iat")},
            )
        )

    if nbf is not None and iat is not None and nbf < iat:
        findings.append(
            Finding(
                check=CHECK_NAME,
                title="nbf predates iat",
                description=(
                    f"nbf ({nbf:.0f}) is earlier than iat ({iat:.0f}) — the token "
                    "claims to be valid before it was issued. This is logically "
                    "inconsistent and may indicate a clock issue on the issuer or "
                    "a hand-crafted/forged token."
                ),
                severity="low",
                evidence={"nbf": nbf, "iat": iat},
            )
        )

    if exp is not None and iat is not None:
        lifetime = exp - iat
        if lifetime > threshold:
            findings.append(
                Finding(
                    check=CHECK_NAME,
                    title="Unusually long token lifetime",
                    description=(
                        f"exp - iat is {lifetime:.0f} seconds (~{lifetime / 86400:.0f} days), "
                        f"above the {threshold} second (~{threshold / 86400:.0f} day) threshold. "
                        "Long-lived tokens widen the window an attacker can use a "
                        "stolen token, and make revocation more important since "
                        "there's no natural expiry to rely on."
                    ),
                    severity="medium",
                    evidence={"exp": exp, "iat": iat, "lifetime_seconds": lifetime, "threshold_seconds": threshold},
                )
            )

    return findings
