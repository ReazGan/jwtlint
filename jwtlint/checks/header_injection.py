"""Key-selection header checks: jku, x5u, jwk, x5c, kid.

These headers tell the verifier *where to find the key*. They live in the
header, which the attacker controls, so a verifier that honours them without
an allowlist lets the attacker pick the key used to check their own forgery.

- jku / x5u: URL to fetch a JWK Set / X.509 chain from. Point it at an
  attacker-hosted key and sign with the matching private key. Also an SSRF
  primitive if the server fetches it blindly.
- jwk: the public key embedded inline (CVE-2018-0114 in node-jose). The
  attacker embeds their own key and signs with it.
- x5c: same idea as jwk, with an inline certificate chain.
- kid: a free-form key id. Often used as a filename or DB lookup key, so
  path traversal or SQL fragments here point at injection in the key lookup.
"""

from __future__ import annotations

import re
from typing import Any

from jwtlint.checks.base import Finding
from jwtlint.parser import ParsedToken

CHECK_NAME = "header-injection"

_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|^/|^[a-zA-Z]:\\|/dev/null|/etc/|/proc/)")
_SQL = re.compile(r"('|\"|--|;|\bunion\b|\bselect\b|\bor\s+1\s*=\s*1\b)", re.IGNORECASE)
_SHELL = re.compile(r"(\$\(|`|\|\||&&|\|)")


def check(parsed: ParsedToken) -> list[Finding]:
    header = parsed.header
    findings: list[Finding] = []

    for name in ("jku", "x5u"):
        value = header.get(name)
        if value is not None:
            findings.append(_url_header(name, value))

    if "jwk" in header:
        findings.append(
            Finding(
                check=CHECK_NAME,
                title="embedded jwk header: token carries its own verification key",
                description=(
                    "The header embeds a public key (jwk). A verifier that uses "
                    "this key to check the signature lets anyone sign a token with "
                    "their own private key and embed the matching public key "
                    "(CVE-2018-0114). Keys must come from server-side config, "
                    "never from the token."
                ),
                severity="high",
                evidence={"jwk": header["jwk"]},
            )
        )

    if "x5c" in header:
        findings.append(
            Finding(
                check=CHECK_NAME,
                title="embedded x5c header: token carries its own certificate chain",
                description=(
                    "The header embeds an X.509 chain (x5c). Unless the verifier "
                    "validates that chain against a pinned trust anchor, an "
                    "attacker can supply a self-signed certificate and sign with "
                    "its key."
                ),
                severity="medium",
                evidence={"certs": len(header["x5c"]) if isinstance(header["x5c"], list) else None},
            )
        )

    if "kid" in header:
        findings.extend(_kid(header["kid"]))

    return findings


def _url_header(name: str, value: Any) -> Finding:
    return Finding(
        check=CHECK_NAME,
        title=f"{name} header present: key is fetched from a URL ({value})",
        description=(
            f"The header tells the verifier to fetch its key from {name}={value!r}. "
            "If the server follows this URL without a strict allowlist, an "
            "attacker can host their own key and sign forged tokens with it. "
            "A blind fetch is also a server-side request forgery vector. "
            "Ignore this header or pin it to a fixed, trusted URL."
        ),
        severity="high",
        evidence={name: value},
    )


def _kid(value: Any) -> list[Finding]:
    if not isinstance(value, str):
        return [
            Finding(
                check=CHECK_NAME,
                title=f"kid is not a string ({type(value).__name__})",
                description=(
                    "RFC 7515 defines kid as a string. A non-string kid can trip "
                    "type-confusion bugs in the key lookup."
                ),
                severity="low",
                evidence={"kid": value},
            )
        ]

    hits = []
    if _TRAVERSAL.search(value):
        hits.append("path traversal")
    if _SQL.search(value):
        hits.append("SQL injection")
    if _SHELL.search(value):
        hits.append("command injection")

    if not hits:
        return []

    kinds = ", ".join(hits)
    return [
        Finding(
            check=CHECK_NAME,
            title=f"suspicious kid value ({kinds}): {value!r}",
            description=(
                f"The kid header looks like a {kinds} payload. Servers often use "
                "kid as a filename or database key when loading the signing "
                "key. A classic trick is kid=../../dev/null so the key becomes "
                "an empty string, then signing with an empty HMAC secret. "
                "Treat kid as an opaque id and look it up in a fixed map."
            ),
            severity="high",
            evidence={"kid": value, "patterns": hits},
        )
    ]
