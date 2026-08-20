"""RS-to-HS algorithm confusion check.

A static analyzer looking only at the token can't know what algorithm the
server actually expects — that's server-side configuration, not something
encoded in the token itself. `--expect-alg` lets the caller supply that
context (e.g. "I know this service is configured for RS256").

The attack: if a server verifies RS256/ES256 tokens using its RSA/EC
*public* key, and an attacker submits an HS256 token instead, some JWT
libraries will happily use whatever key material they're handed as the
HMAC secret. Since the RSA public key is, by definition, public, the
attacker can compute a valid HMAC signature over a forged token using the
public key as the secret — and the server verifies it as authentic. This
only matters if the verifier is naive enough to trust the `alg` from the
attacker-controlled header instead of pinning the expected algorithm.
"""

from __future__ import annotations

from jwtlint.checks.base import Finding
from jwtlint.parser import ParsedToken

CHECK_NAME = "alg-confusion"

_HMAC_ALGS = {"HS256", "HS384", "HS512"}
_ASYMMETRIC_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}


def check(parsed: ParsedToken, expect_alg: str | None = None) -> list[Finding]:
    if not expect_alg:
        return []

    alg = parsed.header.get("alg")
    if not isinstance(alg, str):
        return []

    expect_alg_upper = expect_alg.upper()
    alg_upper = alg.upper()

    if alg_upper == expect_alg_upper:
        return []

    if alg_upper in _HMAC_ALGS and expect_alg_upper in _ASYMMETRIC_ALGS:
        return [
            Finding(
                check=CHECK_NAME,
                title=f"algorithm confusion risk: token uses {alg}, server expects {expect_alg}",
                description=(
                    f"This token's header specifies alg={alg} (HMAC), but the "
                    f"server was told to expect {expect_alg} (RSA/EC, asymmetric). "
                    "This is the classic RS-to-HS confusion attack: if the "
                    "verifier passes its RSA/EC *public* key into an HMAC "
                    "verification routine whenever the header says alg=HS*, an "
                    "attacker can sign a forged token with HMAC-SHA256 using the "
                    "public key (which is, by definition, known to the attacker) "
                    "as the secret, and the server will treat it as validly "
                    "signed. A safe verifier must pin the expected algorithm "
                    "server-side and reject any token whose header claims a "
                    "different one, rather than trusting alg from attacker-"
                    "controlled input."
                ),
                severity="critical",
                evidence={"token_alg": alg, "expected_alg": expect_alg},
            )
        ]

    return [
        Finding(
            check=CHECK_NAME,
            title=f"algorithm mismatch: token uses {alg}, server expects {expect_alg}",
            description=(
                f"The token's alg ({alg}) does not match the expected algorithm "
                f"({expect_alg}). A verifier that doesn't strictly pin/allowlist "
                "the algorithm may accept tokens signed under a weaker or "
                "unintended scheme."
            ),
            severity="medium",
            evidence={"token_alg": alg, "expected_alg": expect_alg},
        )
    ]
