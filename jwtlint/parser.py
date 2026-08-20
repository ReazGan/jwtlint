"""Raw JWT structure parsing.

Deliberately does not use a JWT library. A security analyzer needs to reason
about the raw three-segment structure (including cases a permissive decoder
library would normalize away or refuse to touch, e.g. `alg: none`), so the
base64url decode and JSON parse are done by hand here per RFC 7519 / RFC 7515.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any


class TokenParseError(Exception):
    """Raised when input cannot be parsed as a structurally valid JWT."""


@dataclass
class ParsedToken:
    raw: str
    header_segment: str
    payload_segment: str
    signature_segment: str
    header: dict[str, Any]
    payload: dict[str, Any]

    @property
    def signing_input(self) -> bytes:
        """`base64url(header) + "." + base64url(payload)` — the exact bytes
        that are signed/verified per RFC 7515."""
        return f"{self.header_segment}.{self.payload_segment}".encode("ascii")

    @property
    def signature_bytes(self) -> bytes:
        return _b64url_decode(self.signature_segment) if self.signature_segment else b""


def _b64url_decode(segment: str) -> bytes:
    """base64url-decode a JWT segment, restoring the padding JWTs omit."""
    padding_needed = (-len(segment)) % 4
    padded = segment + ("=" * padding_needed)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise TokenParseError(f"invalid base64url encoding: {exc}") from exc


def _b64url_decode_json(segment: str, part_name: str) -> dict[str, Any]:
    raw_bytes = _b64url_decode(segment)
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TokenParseError(f"{part_name} is not valid UTF-8: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise TokenParseError(f"{part_name} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise TokenParseError(f"{part_name} JSON must be an object, got {type(data).__name__}")
    return data


def parse(token: str) -> ParsedToken:
    """Split and decode a compact-serialization JWT into its three segments.

    Raises TokenParseError with a clear, non-stack-trace message for any
    malformed input: wrong segment count, bad base64url, bad JSON, or a
    non-object header/payload.
    """
    token = token.strip()
    if not token:
        raise TokenParseError("empty input")

    segments = token.split(".")
    if len(segments) != 3:
        raise TokenParseError(
            f"expected 3 dot-separated segments (header.payload.signature), got {len(segments)}"
        )

    header_segment, payload_segment, signature_segment = segments

    if not header_segment:
        raise TokenParseError("header segment is empty")
    if not payload_segment:
        raise TokenParseError("payload segment is empty")

    header = _b64url_decode_json(header_segment, "header")
    payload = _b64url_decode_json(payload_segment, "payload")

    return ParsedToken(
        raw=token,
        header_segment=header_segment,
        payload_segment=payload_segment,
        signature_segment=signature_segment,
        header=header,
        payload=payload,
    )
