"""State-verification tests (Terra M2.4).

Readback persistence, idempotency re-checks, token-lifecycle checks,
JSONPath assertions, and orchestrator upgrade/downgrade wiring.
No network in any test.
"""
import json

from apex_fuzzer.verify.base import (
    verify_persisted, verify_idempotency, verify_token_reuse,
    VERIFIED, REFUTED, INCONCLUSIVE, StateVerifier)
from apex_fuzzer.verify.assertions import (
    jsonpath_get, check_rule, evaluate_assertions,
    matching_assertions)
from apex_fuzzer.models import Endpoint, Parameter, Identity
from apex_fuzzer.config import Config


class FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.headers = {}


def _ep(url, qparams=None, bparams=None):
    from apex_fuzzer.discovery.url_normalizer import normalize_url
    from urllib.parse import urlparse
    p = urlparse(url)
    e = Endpoint(url=url, normalized_url=normalize_url(url),
                 host=p.hostname or "", path=p.path,
                 endpoint_type="api", source=["recon"])
    for n, v in (qparams or []):
        e.query_parameters.append(Parameter(
            name=n, location="query", source=["url"], sample_value=v))
    for n in (bparams or []):
        e.body_parameters.append(Parameter(name=n, location="body",
                                            source=["html"]))
    return e


# ── persistence readback ────────────────────────────────────────────
def test_persisted_verified():
    class H:
        def get(self, url, **kw):
            return FakeResp(200, json.dumps({"cart": {"qty": -1}}))

    r = verify_persisted(H(), "https://t.com/cart", {}, "qty", -1)
    assert r.status == VERIFIED
    assert "-1" in r.detail and r.evidence["read_url"].endswith("/cart")


def test_persisted_refuted_on_clean_reread():
    class H:
        def get(self, url, **kw):
            return FakeResp(200, json.dumps({"cart": {"qty": 2}}))

    r = verify_persisted(H(), "https://t.com/cart", {}, "qty", -1)
    assert r.status == REFUTED
    assert "did not persist" in r.detail


def test_persisted_inconclusive_paths():
    class Fail:
        def get(self, url, **kw):
            raise ConnectionError("down")

    assert verify_persisted(
        Fail(), "https://t.com/c", {}, "qty", -1).status == INCONCLUSIVE

    class Non200:
        def get(self, url, **kw):
            return FakeResp(403, "denied")

    assert verify_persisted(
        Non200(), "https://t.com/c", {}, "qty", -1).status == \
        INCONCLUSIVE

    class NotJson:
        def get(self, url, **kw):
            return FakeResp(200, "<html>hi</html>")

    assert verify_persisted(
        NotJson(), "https://t.com/c", {}, "qty", -1).status == \
        INCONCLUSIVE

    class NoField:
        def get(self, url, **kw):
            return FakeResp(200, json.dumps({"other": 1}))

    assert verify_persisted(
        NoField(), "https://t.com/c", {}, "qty", -1).status == \
        INCONCLUSIVE


# ── idempotency ───────────────────────────────────────────────────────
def test_idempotency_double_accept_verified():
    n = [0]

    class H:
        def post(self, url, **kw):
            n[0] += 1
            return FakeResp(200, json.dumps({"transaction_id": n[0]}))

    r = verify_idempotency(H(), "POST", "https://t.com/pay",
                           {"amt": "5"}, {}, "Idempotency-Key")
    assert r.status == VERIFIED
    assert "different objects" in r.detail


def test_idempotency_second_rejected():
    class H:
        def post(self, url, **kw):
            if not hasattr(H, "seen"):
                H.seen = True
                return FakeResp(200, json.dumps({"transaction_id": 1}))
            return FakeResp(409, "duplicate")

    if hasattr(H, "seen"):
        del H.seen
    r = verify_idempotency(H(), "POST", "https://t.com/pay",
                           {"amt": "5"}, {}, "Idempotency-Key")
    assert r.status == REFUTED
    assert "correctly rejected" in r.detail


def test_idempotency_identical_ids_inconclusive():
    class H:
        def post(self, url, **kw):
            return FakeResp(200, json.dumps({"transaction_id": 7}))

    r = verify_idempotency(H(), "POST", "https://t.com/pay", {}, {},
                           "Idempotency-Key")
    assert r.status == INCONCLUSIVE


# ── token lifecycle ───────────────────────────────────────────────────
def test_token_reuse_verified():
    class H:
        def post(self, url, **kw):
            return FakeResp(200, json.dumps({"ok": True, "by": "x"}))

    r = verify_token_reuse(H(), "POST", "https://t.com/redeem",
                           {"c": "X"}, {})
    assert r.status == VERIFIED


def test_token_second_rejected_is_refuted():
    calls = []

    class H:
        def post(self, url, **kw):
            calls.append(1)
            if len(calls) == 1:
                return FakeResp(200, json.dumps({"ok": True}))
            return FakeResp(410, "used")

    r = verify_token_reuse(H(), "POST", "https://t.com/redeem",
                           {"c": "X"}, {})
    assert r.status == REFUTED


def test_token_get_with_query():
    seen = []

    class H:
        def get(self, url, **kw):
            seen.append(url)
            return FakeResp(200, json.dumps({"ok": True}))

    r = verify_token_reuse(H(), "GET", "https://t.com/r?a=1",
                           {}, {}, query={"c": "X"})
    assert r.status == VERIFIED
    # query replaced, not duplicated onto the baseline query string
    assert seen[0].count("c=") == 1 and "a=1" not in seen[0]


# ── JSONPath assertions ───────────────────────────────────────────────
def test_jsonpath_subset():
    data = {"cart": {"qty": -1},
            "items": [{"sku": "A", "qty": 2}, {"sku": "B", "qty": 0}]}
    assert jsonpath_get(data, "$.cart.qty") == (True, [-1])
    assert jsonpath_get(data, "$.items[0].sku") == (True, ["A"])
    ok, vals = jsonpath_get(
        data, "$.items[?(@.sku == 'A')].qty")
    assert (ok, vals) == (True, [2])
    assert jsonpath_get(data, "$.missing.deep") == (True, [])
    assert jsonpath_get(data, "$.a[?(@.b)].c") == (False, [])
    assert jsonpath_get(data, "not-a-path") == (False, [])
    assert jsonpath_get(data, "") == (False, [])


def test_check_rules():
    assert check_rule(-1, "gte", 0) is False
    assert check_rule(5, "gte", 0) is True
    assert check_rule("abc", "contains", "b") is True
    assert check_rule("a", "eq", "a") is True
    assert check_rule("a", "ne", "b") is True
    assert check_rule("x", "bogus", "x") is False
    assert check_rule(None, "gte", 0) is False


def test_evaluate_assertions():
    body = json.dumps({"items": [{"sku": "A", "qty": -1}]})
    status, detail, ev = evaluate_assertions(
        [{"jsonpath": "$.items[?(@.sku == 'A')].qty",
          "rule": "gte", "value": 0}], body)
    assert status == "failed"  # violation persists → verified path
    status, _, _ = evaluate_assertions(
        [{"jsonpath": "$.items[?(@.sku == 'A')].qty",
          "rule": "gte", "value": -5}], body)
    assert status == "passed"
    assert evaluate_assertions([], body)[0] == "inconclusive"
    assert evaluate_assertions(
        [{"jsonpath": "$.x", "rule": "bogus", "value": 1}],
        body)[0] == "inconclusive"
    assert evaluate_assertions(
        [{"jsonpath": "$.x", "rule": "eq", "value": 1}],
        "not json")[0] == "inconclusive"


def test_matching_assertions():
    cfg = [{"endpoint": "/api/cart", "parameter": "qty",
            "method": "POST", "after_read": "/api/cart",
            "checks": []},
           {"endpoint": "/other", "parameter": "qty"}]
    assert len(matching_assertions(cfg, "/api/cart", "qty", "POST")) \
        == 1
    assert matching_assertions(cfg, "/api/cart", "price", "POST") == \
        []
    assert matching_assertions(cfg, "/api/cart", "qty", "GET") == []
    assert matching_assertions("not-a-list", "/x", "y", "GET") == []


def test_verifier_interface():
    v = StateVerifier()
    try:
        v.verify(http=None, endpoint_url="", method="GET",
                 headers={}, timeout=1, context={})
        raise AssertionError("base must not implement verify")
    except NotImplementedError:
        pass
    assert v.name == "base"


# ── orchestrator wiring ───────────────────────────────────────────────
def _biz_http(store):
    class H:
        def get(self, url, **kw):
            from urllib.parse import urlsplit, parse_qsl
            q = dict(parse_qsl(urlsplit(url).query))
            if "/cart" in url and "qty" not in q:
                # clean re-read: persisted state (echoes mutation)
                return FakeResp(200, json.dumps(
                    {"qty": int(store.get("qty", 2))}))
            return FakeResp(200, json.dumps({"echo": q}))

        def post(self, url, **kw):
            return FakeResp(200, "ok")

    return H()


def test_business_verified_upgrade_and_metrics():
    import tempfile
    from pathlib import Path
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.profiles import get as get_profile
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    out = Path(tempfile.mkdtemp())
    cfg = Config()
    store = {"qty": -1}  # server persisted the abuse value
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    eps = [_ep("https://t.com/cart?qty=2", [("qty", "2")])]
    m = Metrics()
    found = orch._business_logic_probe(
        eps, EvidenceStore(out / "proofs"), m, BudgetTracker(cfg),
        CoverageTracker(), _biz_http(store),
        [Identity(name="user_a")])
    assert len(found) == 1
    f = found[0]
    assert f.validation_status == "confirmed"
    assert f.confidence == "confirmed"
    assert "verified-effect" in f.tags
    assert m.effects_verified == 1
    assert "Persistence CONFIRMED" in f.false_positive_notes


def test_business_refuted_downgrade():
    import tempfile
    from pathlib import Path
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.profiles import get as get_profile
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    out = Path(tempfile.mkdtemp())
    cfg = Config()
    store = {"qty": 2}  # clean re-read: effect did NOT persist
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    eps = [_ep("https://t.com/cart?qty=2", [("qty", "2")])]
    found = orch._business_logic_probe(
        eps, EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), CoverageTracker(), _biz_http(store),
        [Identity(name="user_a")])
    assert len(found) == 1
    assert found[0].validation_status == "inconclusive"
    assert "not persisted" in found[0].name


def test_race_idempotency_upgrade():
    import tempfile
    from pathlib import Path
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.profiles import get as get_profile
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    n = [0]

    class H:
        def post(self, url, **kw):
            n[0] += 1
            return FakeResp(200, json.dumps({"transaction_id": n[0]}))

    out = Path(tempfile.mkdtemp())
    cfg = Config()
    cfg.race.concurrency = 2
    cfg.race.rounds = 1
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    ep = _ep("https://t.com/pay", [], "api")
    ep.body_parameters.append(__import__(
        "apex_fuzzer.models", fromlist=["Parameter"]).Parameter(
            name="Idempotency-Key", location="header",
            source=["test"], sample_value="K1"))
    # header-located params are not sent as body; put key in body too
    from apex_fuzzer.models import Parameter as P
    ep.body_parameters.append(P(name="idem_key", location="body",
                                source=["test"], sample_value="K1"))
    m = Metrics()
    found = orch._race_probe(
        [ep], EvidenceStore(out / "proofs"), m, BudgetTracker(cfg),
        CoverageTracker(), H(), [Identity(name="user_a")])
    assert found and found[0].validation_status == "confirmed"
    assert "verified-effect" in found[0].tags
    assert m.effects_verified == 1


def test_race_no_key_stays_candidate():
    import tempfile
    from pathlib import Path
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.profiles import get as get_profile
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    from apex_fuzzer.models import Parameter as P
    n = [0]

    class H:
        def post(self, url, **kw):
            n[0] += 1
            return FakeResp(200, json.dumps({"id": n[0]}))

    out = Path(tempfile.mkdtemp())
    cfg = Config()
    cfg.race.concurrency = 2
    cfg.race.rounds = 1
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    ep = _ep("https://t.com/make", [], "api")
    ep.body_parameters.append(P(name="name", location="body",
                                source=["test"], sample_value="x"))
    found = orch._race_probe(
        [ep], EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), CoverageTracker(), H(),
        [Identity(name="user_a")])
    assert found and found[0].validation_status == "strong_candidate"
    assert "verified-effect" not in found[0].tags
