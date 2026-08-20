"""Real tests against real (hand-built and PyJWT-generated) JWTs.

PyJWT is used here only as a fixture-generation convenience (see
requirements-test.txt) — every assertion exercises jwtlint's own parser and
checks, not PyJWT's.
"""

from __future__ import annotations

import base64
import json
import time

import jwt as pyjwt  # PyJWT, test-fixture generation only
import pytest

from jwtlint.checks import run_all
from jwtlint.checks.crack import try_crack
from jwtlint.parser import TokenParseError, parse
from jwtlint.wordlist import DEFAULT_WORDLIST


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _hand_build_none_token(payload: dict) -> str:
    """Build an alg:none token by hand, segment by segment, to prove the
    parser handles the raw structure without going through any JWT library."""
    header = {"alg": "none", "typ": "JWT"}
    header_seg = _b64url(json.dumps(header).encode())
    payload_seg = _b64url(json.dumps(payload).encode())
    return f"{header_seg}.{payload_seg}."


def _findings_by_check(findings, check_name):
    return [f for f in findings if f["check"] == check_name]


def _severities(findings):
    return {f["severity"] for f in findings}


class TestParser:
    def test_valid_token_round_trips_header_and_payload(self):
        token = pyjwt.encode({"sub": "user-1", "exp": int(time.time()) + 3600}, "some-secret", algorithm="HS256")
        parsed = parse(token)
        assert parsed.header["alg"] == "HS256"
        assert parsed.payload["sub"] == "user-1"

    def test_wrong_segment_count_raises_clear_error(self):
        with pytest.raises(TokenParseError, match="3 dot-separated segments"):
            parse("not.a.valid.jwt.at.all")

    def test_single_string_raises_clear_error(self):
        with pytest.raises(TokenParseError):
            parse("this-is-not-a-jwt")

    def test_invalid_base64_raises_clear_error(self):
        with pytest.raises(TokenParseError, match="base64"):
            parse("!!!not-base64!!!.!!!also-not!!!.sig")

    def test_invalid_json_raises_clear_error(self):
        header_seg = _b64url(b"not-json-at-all")
        payload_seg = _b64url(b'{"a": 1}')
        with pytest.raises(TokenParseError, match="JSON"):
            parse(f"{header_seg}.{payload_seg}.sig")

    def test_empty_string_raises_clear_error(self):
        with pytest.raises(TokenParseError, match="empty"):
            parse("")

    def test_missing_padding_is_handled(self):
        # base64url segments in real JWTs are unpadded; verify the decoder
        # restores padding correctly rather than choking on it.
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "x"}
        header_seg = _b64url(json.dumps(header).encode())
        payload_seg = _b64url(json.dumps(payload).encode())
        assert "=" not in header_seg and "=" not in payload_seg
        parsed = parse(f"{header_seg}.{payload_seg}.fakesig")
        assert parsed.header == header
        assert parsed.payload == payload


class TestAlgNone:
    def test_alg_none_flagged_critical(self):
        token = _hand_build_none_token({"sub": "attacker", "admin": True})
        parsed = parse(token)
        findings = run_all(parsed)
        alg_none_findings = _findings_by_check(findings, "alg-none")
        assert len(alg_none_findings) == 1
        assert alg_none_findings[0]["severity"] == "critical"
        assert "critical" in _severities(findings)

    @pytest.mark.parametrize("alg_variant", ["none", "None", "NONE", "nOnE"])
    def test_case_variants_of_none_are_caught(self, alg_variant):
        header_seg = _b64url(json.dumps({"alg": alg_variant, "typ": "JWT"}).encode())
        payload_seg = _b64url(json.dumps({"sub": "x"}).encode())
        parsed = parse(f"{header_seg}.{payload_seg}.")
        findings = run_all(parsed)
        assert _findings_by_check(findings, "alg-none")

    def test_normal_hs256_token_not_flagged_as_alg_none(self):
        token = pyjwt.encode({"sub": "user-1", "exp": int(time.time()) + 3600}, "s3cr3t-not-in-wordlist-xyz", algorithm="HS256")
        parsed = parse(token)
        findings = run_all(parsed)
        assert not _findings_by_check(findings, "alg-none")


class TestAlgConfusion:
    def test_hs256_token_flagged_when_rs256_expected(self):
        token = pyjwt.encode({"sub": "user-1", "exp": int(time.time()) + 3600}, "secret", algorithm="HS256")
        parsed = parse(token)
        findings = run_all(parsed, expect_alg="RS256")
        confusion = _findings_by_check(findings, "alg-confusion")
        assert len(confusion) == 1
        assert confusion[0]["severity"] == "critical"
        assert "RS256" in confusion[0]["description"]

    def test_no_finding_when_expect_alg_matches(self):
        token = pyjwt.encode({"sub": "user-1", "exp": int(time.time()) + 3600}, "secret", algorithm="HS256")
        parsed = parse(token)
        findings = run_all(parsed, expect_alg="HS256")
        assert not _findings_by_check(findings, "alg-confusion")

    def test_no_finding_when_expect_alg_not_given(self):
        token = pyjwt.encode({"sub": "user-1", "exp": int(time.time()) + 3600}, "secret", algorithm="HS256")
        parsed = parse(token)
        findings = run_all(parsed)
        assert not _findings_by_check(findings, "alg-confusion")


class TestClaims:
    def test_valid_token_has_no_high_or_critical_findings(self):
        now = int(time.time())
        token = pyjwt.encode(
            {"sub": "user-1", "iat": now, "exp": now + 3600},
            "a-reasonably-unguessable-secret-value",
            algorithm="HS256",
        )
        parsed = parse(token)
        findings = run_all(parsed)
        assert "critical" not in _severities(findings)
        assert "high" not in _severities(findings)

    def test_missing_exp_flagged_high(self):
        token = pyjwt.encode({"sub": "user-1", "iat": int(time.time())}, "secret", algorithm="HS256")
        parsed = parse(token)
        findings = run_all(parsed)
        exp_findings = [f for f in findings if f["title"] == "No exp (expiration) claim"]
        assert len(exp_findings) == 1
        assert exp_findings[0]["severity"] == "high"

    def test_expired_token_flagged_info(self):
        past = int(time.time()) - 3600
        token = pyjwt.encode({"sub": "user-1", "iat": past - 3600, "exp": past}, "secret", algorithm="HS256")
        parsed = parse(token)
        findings = run_all(parsed)
        expired = [f for f in findings if f["title"] == "Token is expired"]
        assert len(expired) == 1
        assert expired[0]["severity"] == "info"

    def test_missing_iat_flagged_low(self):
        token = pyjwt.encode({"sub": "user-1", "exp": int(time.time()) + 3600}, "secret", algorithm="HS256")
        parsed = parse(token)
        findings = run_all(parsed)
        iat_findings = [f for f in findings if f["title"] == "No iat (issued-at) claim"]
        assert len(iat_findings) == 1
        assert iat_findings[0]["severity"] == "low"

    def test_overly_long_lifetime_flagged(self):
        now = int(time.time())
        ten_years = 10 * 365 * 24 * 3600
        token = pyjwt.encode({"sub": "user-1", "iat": now, "exp": now + ten_years}, "secret", algorithm="HS256")
        parsed = parse(token)
        findings = run_all(parsed)
        assert any(f["title"] == "Unusually long token lifetime" for f in findings)

    def test_nbf_before_iat_flagged(self):
        now = int(time.time())
        token = pyjwt.encode(
            {"sub": "user-1", "iat": now, "nbf": now - 100, "exp": now + 3600},
            "secret",
            algorithm="HS256",
        )
        parsed = parse(token)
        findings = run_all(parsed)
        assert any(f["title"] == "nbf predates iat" for f in findings)


class TestCrack:
    def test_cracks_token_signed_with_known_weak_secret(self):
        weak_secret = DEFAULT_WORDLIST[0]
        assert weak_secret == "secret"
        token = pyjwt.encode({"sub": "user-1", "exp": int(time.time()) + 3600}, weak_secret, algorithm="HS256")
        parsed = parse(token)

        cracked = try_crack(parsed, DEFAULT_WORDLIST)

        assert cracked == weak_secret

    def test_does_not_crack_strong_secret_not_in_wordlist(self):
        token = pyjwt.encode(
            {"sub": "user-1", "exp": int(time.time()) + 3600},
            "x9f2-not-in-any-wordlist-Kj3mQ7",
            algorithm="HS256",
        )
        parsed = parse(token)

        cracked = try_crack(parsed, DEFAULT_WORDLIST)

        assert cracked is None

    def test_crack_check_reports_critical_finding_on_success(self):
        weak_secret = "changeme"
        assert weak_secret in DEFAULT_WORDLIST
        token = pyjwt.encode({"sub": "user-1", "exp": int(time.time()) + 3600}, weak_secret, algorithm="HS256")
        parsed = parse(token)

        findings = run_all(parsed, crack_wordlist=DEFAULT_WORDLIST)

        crack_findings = _findings_by_check(findings, "hmac-crack")
        assert any(f["severity"] == "critical" and weak_secret in f["description"] for f in crack_findings)

    def test_crack_skipped_for_rs256_alg(self):
        # HS-only check: an RS256-alg header with no real RSA signature should
        # be skipped cleanly rather than erroring.
        header_seg = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload_seg = _b64url(json.dumps({"sub": "x"}).encode())
        parsed = parse(f"{header_seg}.{payload_seg}.fakesig")

        findings = run_all(parsed, crack_wordlist=DEFAULT_WORDLIST)

        crack_findings = _findings_by_check(findings, "hmac-crack")
        assert len(crack_findings) == 1
        assert crack_findings[0]["severity"] == "info"
        assert "skipped" in crack_findings[0]["title"]

    def test_hs512_crack_also_works(self):
        weak_secret = "letmein"
        token = pyjwt.encode({"sub": "user-1", "exp": int(time.time()) + 3600}, weak_secret, algorithm="HS512")
        parsed = parse(token)

        cracked = try_crack(parsed, DEFAULT_WORDLIST)

        assert cracked == weak_secret
