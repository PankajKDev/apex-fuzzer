"""JWT claim tampering: exp/audience/privilege variants on own tokens.

No network. Fake HTTP clients only. Only the test account's own
token is ever mutated — no foreign tokens, no key guessing.
"""
import base64
import json
from types import SimpleNamespace

from main.budgets import BudgetExceeded
from main.validation import jwt_replay as jwt_mod


def _token(payload, header=None):
    def seg(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj).encode()).rstrip(b"=").decode()
    return (f"{seg(header or {'alg': 'HS256', 'typ': 'JWT'})}."
            f"{seg(payload)}.sig")


def _claims(token):
    from main.auth.jwt import parse_jwt
    return parse_jwt(token).payload


def test_exp_removed_drops_only_exp():
    variants = dict(jwt_mod.claim_variants(
        _token({"sub": "u1", "exp": 999, "role": "admin"})))
    assert "exp-removed" in variants
    mutated = _claims(variants["exp-removed"])
    assert "exp" not in mutated
    assert mutated["sub"] == "u1"
    # header and signature segments preserved byte-identical
    assert variants["exp-removed"].split(".")[0] == \
        _token({"sub": "u1"}).split(".")[0]
    assert variants["exp-removed"].endswith(".sig")


def test_aud_mismatched_replaces_audience():
    variants = dict(jwt_mod.claim_variants(
        _token({"sub": "u1", "aud": "real-api"})))
    assert variants["aud-mismatched"].endswith(".sig")
    assert _claims(variants["aud-mismatched"])["aud"] == \
        jwt_mod._INVALID_AUDIENCE


def test_privilege_upgraded_preserves_type():
    variants = dict(jwt_mod.claim_variants(
        _token({"sub": "u1", "role": "user"})))
    assert _claims(variants["privilege-upgraded"])["role"] == "admin"
    variants = dict(jwt_mod.claim_variants(
        _token({"sub": "u1", "is_admin": False})))
    assert _claims(variants["privilege-upgraded"])["is_admin"] is True
    variants = dict(jwt_mod.claim_variants(
        _token({"sub": "u1", "groups": ["dev"]})))
    assert _claims(variants["privilege-upgraded"])["groups"] == ["admin"]


def test_privilege_injected_when_absent():
    variants = dict(jwt_mod.claim_variants(_token({"sub": "u1"})))
    assert _claims(variants["privilege-injected"])["role"] == "admin"


def test_already_privileged_token_gets_no_privilege_variant():
    variants = dict(jwt_mod.claim_variants(
        _token({"sub": "u1", "role": "admin"})))
    assert "privilege-upgraded" not in variants
    assert "privilege-injected" not in variants


def test_variant_count_is_capped():
    variants = jwt_mod.claim_variants(
        _token({"sub": "u1", "exp": 1, "aud": "a", "role": "user"}))
    assert len(variants) == 3
    assert [label for label, _ in variants] == [
        "exp-removed", "aud-mismatched", "privilege-upgraded"]


def test_malformed_token_yields_nothing():
    assert jwt_mod.claim_variants("not-a-jwt") == []
    assert jwt_mod.claim_variants("") == []


class _SelectiveHttp:
    """Baseline 200; confusion denied; exp-removed accepted like baseline."""

    def __init__(self, token):
        self.token = token

    def get(self, url, **kwargs):
        auth = str((kwargs.get("headers") or {}).get("Authorization",
                                                     ""))
        if auth == f"Bearer {self.token}":
            return SimpleNamespace(status_code=200,
                                   text='{"user":"u1"}', headers={})
        if ".sig" in auth and "none" not in auth:
            import base64 as _b64
            payload = auth.split(" ")[1].split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims = json.loads(_b64.urlsafe_b64decode(payload))
            if "exp" not in claims:
                return SimpleNamespace(status_code=200,
                                       text='{"user":"u1"}', headers={})
        return SimpleNamespace(status_code=401, text="denied",
                               headers={})


def test_claim_acceptance_is_candidate_with_reason():
    token = _token({"sub": "u1", "exp": 9999999999})
    headers = {"Authorization": f"Bearer {token}"}
    res = jwt_mod.jwt_confusion_probe(
        _SelectiveHttp(token), "https://example.test/api/me", headers,
        "tester")
    assert res.verdict == "accepted"
    assert "exp-removed" in res.notes
    assert "expiry" in res.notes


def test_all_denied_is_genuine_negative():
    class Http:
        def __init__(self, token):
            self.token = token

        def get(self, url, **kwargs):
            auth = str((kwargs.get("headers") or {}).get(
                "Authorization", ""))
            if auth == f"Bearer {self.token}":
                return SimpleNamespace(status_code=200,
                                       text='{"user":"u1"}', headers={})
            return SimpleNamespace(status_code=401, text="denied",
                                   headers={})

    token = _token({"sub": "u1", "exp": 1})
    res = jwt_mod.jwt_confusion_probe(
        Http(token), "https://example.test/api/me",
        {"Authorization": f"Bearer {token}"}, "tester")
    assert res.verdict == "denied"


def test_token_values_never_reach_notes_or_evidence():
    token = _token({"sub": "victim-99", "role": "superuser-7"})
    headers = {"Authorization": f"Bearer {token}"}
    res = jwt_mod.jwt_confusion_probe(
        _SelectiveHttp(token), "https://example.test/api/me", headers,
        "tester")
    assert "victim-99" not in res.notes
    assert "superuser-7" not in res.notes
    assert "victim-99" not in json.dumps(res.evidence)


def test_budget_propagates():
    class Http:
        def get(self, *a, **k):
            raise BudgetExceeded("spent")

    try:
        jwt_mod.jwt_confusion_probe(
            Http(), "https://example.test/api/me",
            {"Authorization": f"Bearer {_token({'sub': 'u1'})}"},
            "tester")
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")
