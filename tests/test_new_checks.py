"""Header-injection, sensitive-data and CLI input tests."""

from __future__ import annotations

import base64
import json
import time

import jwt as pyjwt  # PyJWT, test-fixture generation only
from click.testing import CliRunner

from jwtlint.checks import run_all
from jwtlint.cli import main
from jwtlint.parser import parse


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _token(header: dict, payload: dict) -> str:
    return f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}.c2ln"


def _clean_payload(**extra):
    now = int(time.time())
    return {"sub": "u1", "iat": now, "exp": now + 3600, **extra}


def _by_check(findings, name):
    return [f for f in findings if f["check"] == name]


class TestHeaderInjection:
    def test_jku_flagged_high(self):
        t = _token({"alg": "RS256", "jku": "https://evil.example/jwks.json"}, _clean_payload())
        hits = _by_check(run_all(parse(t)), "header-injection")
        assert len(hits) == 1
        assert hits[0]["severity"] == "high"
        assert "jku" in hits[0]["title"]

    def test_x5u_flagged(self):
        t = _token({"alg": "RS256", "x5u": "http://10.0.0.1/cert.pem"}, _clean_payload())
        assert _by_check(run_all(parse(t)), "header-injection")[0]["evidence"]["x5u"] == "http://10.0.0.1/cert.pem"

    def test_embedded_jwk_flagged(self):
        jwk = {"kty": "RSA", "n": "abc", "e": "AQAB"}
        t = _token({"alg": "RS256", "jwk": jwk}, _clean_payload())
        hits = _by_check(run_all(parse(t)), "header-injection")
        assert hits[0]["severity"] == "high"
        assert "jwk" in hits[0]["title"]

    def test_x5c_flagged_medium(self):
        t = _token({"alg": "RS256", "x5c": ["MIIB", "MIIC"]}, _clean_payload())
        hits = _by_check(run_all(parse(t)), "header-injection")
        assert hits[0]["severity"] == "medium"
        assert hits[0]["evidence"]["certs"] == 2

    def test_kid_path_traversal(self):
        t = _token({"alg": "HS256", "kid": "../../../../dev/null"}, _clean_payload())
        hits = _by_check(run_all(parse(t)), "header-injection")
        assert "path traversal" in hits[0]["evidence"]["patterns"]

    def test_kid_sql_injection(self):
        t = _token({"alg": "HS256", "kid": "x' UNION SELECT 'secret"}, _clean_payload())
        hits = _by_check(run_all(parse(t)), "header-injection")
        assert "SQL injection" in hits[0]["evidence"]["patterns"]

    def test_kid_command_injection(self):
        t = _token({"alg": "HS256", "kid": "key1|whoami"}, _clean_payload())
        assert "command injection" in _by_check(run_all(parse(t)), "header-injection")[0]["evidence"]["patterns"]

    def test_normal_kid_is_clean(self):
        for kid in ("2024-rotation-1", "a1b2c3d4", "key_prod.v2"):
            t = _token({"alg": "RS256", "kid": kid}, _clean_payload())
            assert _by_check(run_all(parse(t)), "header-injection") == []

    def test_non_string_kid_low(self):
        t = _token({"alg": "RS256", "kid": 7}, _clean_payload())
        assert _by_check(run_all(parse(t)), "header-injection")[0]["severity"] == "low"

    def test_real_pyjwt_token_has_no_header_findings(self):
        t = pyjwt.encode(_clean_payload(), "s3cr3t-value-long-enough-for-hs256!!", algorithm="HS256", headers={"kid": "k1"})
        assert _by_check(run_all(parse(t)), "header-injection") == []


class TestSensitiveData:
    def test_password_claim_high(self):
        t = _token({"alg": "HS256"}, _clean_payload(password="hunter2"))
        hits = _by_check(run_all(parse(t)), "sensitive-data")
        assert hits[0]["severity"] == "high"
        assert hits[0]["evidence"]["claim"] == "password"

    def test_nested_and_camel_case(self):
        t = _token({"alg": "HS256"}, _clean_payload(user={"apiKey": "abc123"}))
        hits = _by_check(run_all(parse(t)), "sensitive-data")
        assert hits[0]["evidence"]["claim"] == "user.apiKey"

    def test_pii_claim_medium(self):
        t = _token({"alg": "HS256"}, _clean_payload(tckn="12345678901"))
        assert _by_check(run_all(parse(t)), "sensitive-data")[0]["severity"] == "medium"

    def test_aws_key_in_value(self):
        t = _token({"alg": "HS256"}, _clean_payload(note="AKIAIOSFODNN7EXAMPLE"))
        assert "AWS" in _by_check(run_all(parse(t)), "sensitive-data")[0]["title"]

    def test_card_number_needs_luhn(self):
        valid = _token({"alg": "HS256"}, _clean_payload(note="4111 1111 1111 1111"))
        invalid = _token({"alg": "HS256"}, _clean_payload(note="1234 5678 9012 3456"))
        assert _by_check(run_all(parse(valid)), "sensitive-data")
        assert _by_check(run_all(parse(invalid)), "sensitive-data") == []

    def test_no_false_positives_on_common_claims(self):
        payload = _clean_payload(
            token_type="Bearer",
            shipping="express",
            role="admin",
            email_verified=True,
            scope="read write",
            password_changed_at=None,
        )
        t = _token({"alg": "HS256"}, payload)
        assert _by_check(run_all(parse(t)), "sensitive-data") == []


class TestCliInput:
    def _valid(self):
        return pyjwt.encode(_clean_payload(), "s3cr3t-value-long-enough-for-hs256!!", algorithm="HS256")

    def test_reads_stdin(self):
        r = CliRunner().invoke(main, ["--json"], input=self._valid() + "\n")
        assert r.exit_code == 0, r.output
        assert '"sub": "u1"' in r.output

    def test_dash_reads_stdin(self):
        r = CliRunner().invoke(main, ["-", "--json"], input=self._valid())
        assert r.exit_code == 0, r.output

    def test_strips_bearer_and_authorization_prefix(self):
        for prefix in ("Bearer ", "Authorization: Bearer "):
            r = CliRunner().invoke(main, [prefix + self._valid(), "--json"])
            assert r.exit_code == 0, r.output

    def test_jku_makes_exit_code_1(self):
        t = _token({"alg": "RS256", "jku": "https://evil.example/k"}, _clean_payload())
        assert CliRunner().invoke(main, [t]).exit_code == 1

    def test_zero_findings_summary_has_no_dangling_dash(self):
        r = CliRunner().invoke(main, [self._valid()])
        assert "0 findings\n" in r.output
