"""Offline HMAC secret brute force for HS256/HS384/HS512 tokens.

For each candidate key, recomputes HMAC-SHA{256,384,512} over the token's
signing input (`base64url(header) + "." + base64url(payload)`, per RFC 7515)
using Python's `hmac`/`hashlib` directly, and compares it to the token's
actual signature bytes with a constant-time comparison. This is entirely
local/offline — no network calls, no interaction with any server.
"""

from __future__ import annotations

import hashlib
import hmac

from jwtlint.checks.base import Finding
from jwtlint.parser import ParsedToken

CHECK_NAME = "hmac-crack"

_HASH_FOR_ALG = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def try_crack(parsed: ParsedToken, wordlist: list[str]) -> str | None:
    """Return the cracked secret, or None if nothing in the wordlist matches."""
    alg = parsed.header.get("alg")
    if not isinstance(alg, str):
        return None

    hash_fn = _HASH_FOR_ALG.get(alg.upper())
    if hash_fn is None:
        return None

    target_sig = parsed.signature_bytes
    if not target_sig:
        return None

    signing_input = parsed.signing_input

    for candidate in wordlist:
        candidate = candidate.strip()
        if not candidate:
            continue
        computed = hmac.new(candidate.encode("utf-8"), signing_input, hash_fn).digest()
        if hmac.compare_digest(computed, target_sig):
            return candidate

    return None


def check(parsed: ParsedToken, wordlist: list[str]) -> list[Finding]:
    alg = parsed.header.get("alg")
    if not isinstance(alg, str) or alg.upper() not in _HASH_FOR_ALG:
        return [
            Finding(
                check=CHECK_NAME,
                title="HMAC crack skipped: alg is not HS256/HS384/HS512",
                description=(
                    f"--crack was passed but the token's alg is {alg!r}, which is "
                    "not an HMAC algorithm. There is no shared secret to brute "
                    "force for asymmetric (RS/ES/PS) or none-algorithm tokens."
                ),
                severity="info",
                evidence={"alg": alg},
            )
        ]

    cracked = try_crack(parsed, wordlist)
    if cracked is not None:
        return [
            Finding(
                check=CHECK_NAME,
                title="HMAC secret cracked",
                description=(
                    f"The signing secret was recovered from the wordlist: {cracked!r}. "
                    "Anyone with this token can now forge arbitrary tokens signed "
                    "with the same key. Rotate the secret and use a high-entropy, "
                    "randomly generated key of at least 256 bits."
                ),
                severity="critical",
                evidence={"alg": alg, "secret": cracked},
            )
        ]

    return [
        Finding(
            check=CHECK_NAME,
            title="HMAC secret not found in wordlist",
            description=(
                f"Tried {len(wordlist)} candidate secret(s) against this {alg} "
                "token; none matched. This does not mean the secret is strong — "
                "only that it isn't in the wordlist tried."
            ),
            severity="info",
            evidence={"alg": alg, "attempts": len(wordlist)},
        )
    ]
