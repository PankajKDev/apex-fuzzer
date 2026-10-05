"""BOLA write replay (MTN pattern): attacker shape + victim ID + readback.

No network. Fake HTTP clients only.
"""
from types import SimpleNamespace

from main.authorization import write_replay as wr_mod
from main.budgets import BudgetExceeded
from main.config import Config, ScopeConfig
from main.models import Endpoint
from main.scope import Scope


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _endpoint(shapes):
    ep = Endpoint(url="https://example.test/app/updateUser",
                  normalized_url="https://example.test/app/updateUser",
                  method="POST", host="example.test",
                  path="/app/updateUser")
    ep.observed_requests = shapes
    return ep


def _victim():
    return SimpleNamespace(param="id", value="/888", owner="owner",
                           owner_tenant="acme", source="response")


def _tester():
    return SimpleNamespace(name="attacker", tenant="acme",
                           auth_headers={"Cookie": "session=ATTACKER"})


def _owner_headers():
    return {"owner": {"Cookie": "session=OWNER"}}


def _attacker_shape(body="id=%2F333&name=ATTACKER-NAME"):
    return {"identity": "attacker", "method": "POST",
            "url": "https://example.test/app/updateUser",
            "headers": {"Content-Type":
                        "application/x-www-form-urlencoded"},
            "post_data": body,
            "content_type": "application/x-www-form-urlencoded"}


class _ConfirmHttp:
    """Baseline without marker; replay accepted; marker persists."""

    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        return SimpleNamespace(
            status_code=200,
            text='{"id":"/888","name":"VICTIM-NAME"}')

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        # second GET is the post-replay readback: marker persisted
        if method == "GET":
            return SimpleNamespace(
                status_code=200,
                text='{"id":"/888","name":"ATTACKER-NAME"}')
        return SimpleNamespace(
            status_code=200,
            text='{"_id":"/888","result":"updated"}')


def test_accepted_write_confirmed_by_readback():
    http, ep = _ConfirmHttp(), _endpoint([_attacker_shape()])
    # readback served by request() only in this fake; route GETs by order:
    calls = {"n": 0}
    orig_get = http.get

    def get(url, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return orig_get(url, **kwargs)
        return SimpleNamespace(
            status_code=200, text='{"id":"/888","name":"ATTACKER-NAME"}')
    http.get = get
    out = wr_mod.replay_writes(http, ep, [_victim()], _tester(),
                               _owner_headers(), scope=_scope())
    assert len(out) == 1
    res = out[0]
    assert res.verdict == "confirmed"
    assert res.readback == "confirmed-persisted"
    assert res.markers_matched == ["name"]
    assert res.replay_accepted is True


def test_clean_readback_refutes_to_inconclusive():
    class Http:
        def get(self, url, **kwargs):
            return SimpleNamespace(
                status_code=200, text='{"id":"/888","name":"VICTIM-NAME"}')

        def request(self, method, url, **kwargs):
            return SimpleNamespace(
                status_code=200,
                text='{"_id":"/888","result":"updated"}')

    out = wr_mod.replay_writes(Http(), _endpoint([_attacker_shape()]),
                               [_victim()], _tester(), _owner_headers(),
                               scope=_scope())
    assert out[0].verdict == "inconclusive"
    assert out[0].readback == "refuted-clean"


def test_failed_readback_leaves_candidate_standing():
    class Http:
        def get(self, url, **kwargs):
            if "Cookie" in str(kwargs.get("headers")) and \
                    "OWNER" in str(kwargs.get("headers")):
                return SimpleNamespace(
                    status_code=200,
                    text='{"id":"/888","name":"VICTIM-NAME"}')
            return SimpleNamespace(status_code=500, text="error")

    orig_get = Http().get
    calls = {"n": 0}

    class Http2:
        def get(self, url, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return orig_get(url, **kwargs)
            return SimpleNamespace(status_code=500, text="error")

        def request(self, method, url, **kwargs):
            return SimpleNamespace(
                status_code=200,
                text='{"_id":"/888","result":"updated"}')

    out = wr_mod.replay_writes(Http2(), _endpoint([_attacker_shape()]),
                               [_victim()], _tester(), _owner_headers(),
                               scope=_scope())
    assert out[0].verdict == "strong_candidate"
    assert out[0].readback == "unverified"


def test_rejected_replay_is_inconclusive():
    class Http:
        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=200, text='{"id":"/888"}')

        def request(self, method, url, **kwargs):
            return SimpleNamespace(status_code=403, text="denied")

    out = wr_mod.replay_writes(Http(), _endpoint([_attacker_shape()]),
                               [_victim()], _tester(), _owner_headers(),
                               scope=_scope())
    assert out[0].verdict == "inconclusive"
    assert out[0].replay_accepted is False


def test_no_attacker_shape_sends_nothing():
    class Http:
        def get(self, *a, **k):
            raise AssertionError("no baseline without a shape")

        def request(self, *a, **k):
            raise AssertionError("must not send")

    ep = _endpoint([{"identity": "owner", "method": "POST",
                     "url": "https://example.test/app/updateUser",
                     "headers": {"Content-Type":
                                 "application/x-www-form-urlencoded"},
                     "post_data": "id=/888&name=x",
                     "content_type":
                     "application/x-www-form-urlencoded"}])
    out = wr_mod.replay_writes(Http(), ep, [_victim()], _tester(),
                               _owner_headers(), scope=_scope())
    assert "no observed" in out[0].notes


def test_ambiguous_shapes_fail_closed():
    class Http:
        def request(self, *a, **k):
            raise AssertionError("ambiguous must not send")

        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=200, text="{}")

    shapes = [_attacker_shape("id=%2F333&name=AAA"),
              _attacker_shape("id=%2F333&name=BBB")]
    out = wr_mod.replay_writes(Http(), _endpoint(shapes), [_victim()],
                               _tester(), _owner_headers(), scope=_scope())
    assert "ambiguous" in out[0].notes


def test_multipart_shape_is_skipped_without_sending():
    class Http:
        def request(self, *a, **k):
            raise AssertionError("multipart must not send")

        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=200, text="{}")

    ep = _endpoint([{"identity": "attacker", "method": "POST",
                     "url": "https://example.test/app/updateUser",
                     "headers": {"Content-Type":
                                 "multipart/form-data; boundary=b"},
                     "post_data": "--b\r\nok\r\n--b--\r\n",
                     "content_type": "multipart/form-data; boundary=b"}])
    out = wr_mod.replay_writes(Http(), ep, [_victim()], _tester(),
                               _owner_headers(), scope=_scope())
    assert "no observed" in out[0].notes


def test_out_of_scope_replay_is_skipped():
    class Http:
        def request(self, *a, **k):
            raise AssertionError("out of scope must not send")

        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=200, text="{}")

    shape = _attacker_shape()
    shape["url"] = "https://evil.test/app/updateUser"
    ep = _endpoint([shape])
    ep.url = "https://evil.test/app/updateUser"
    ep.normalized_url = "https://evil.test/app/updateUser"
    out = wr_mod.replay_writes(Http(), ep, [_victim()], _tester(),
                               _owner_headers(), scope=_scope())
    assert "in-scope" in out[0].notes


def test_budget_exhaustion_propagates():
    class Http:
        def get(self, *a, **k):
            raise BudgetExceeded("request budget exhausted")

        def request(self, *a, **k):
            raise AssertionError("must not reach replay")

    try:
        wr_mod.replay_writes(Http(), _endpoint([_attacker_shape()]),
                             [_victim()], _tester(), _owner_headers(),
                             scope=_scope())
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_plan_accounts_write_replays():
    from main.safety.preflight import plan_authz_matrix
    base = plan_authz_matrix(2, 3, 5, 3)
    assert base.total == 6 + 24 + 30
    extended = plan_authz_matrix(2, 3, 5, 3, write_replays=4)
    assert extended.total == base.total + 12


def test_read_url_preserves_routing_params():
    url = wr_mod._read_url(
        "https://example.test/app/updateUser?view=full", "id", "/888")
    assert url is not None
    assert "view=full" in url
    assert "id=%2F888" in url


def test_duplicate_victims_replay_once():
    class Http:
        def __init__(self):
            self.replays = 0

        def get(self, url, **kwargs):
            return SimpleNamespace(
                status_code=200, text='{"id":"/888","name":"VICTIM-NAME"}')

        def request(self, method, url, **kwargs):
            self.replays += 1
            return SimpleNamespace(
                status_code=200,
                text='{"_id":"/888","result":"updated"}')

    http = Http()
    out = wr_mod.replay_writes(http, _endpoint([_attacker_shape()]),
                               [_victim(), _victim()], _tester(),
                               _owner_headers(), scope=_scope())
    assert http.replays == 1
    assert len([r for r in out if r.replay_accepted]) == 1


def test_orchestrator_emits_confirmed_write_finding(tmp_path):
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.validation.evidence import EvidenceStore

    cfg = Config()
    cfg.authorization.write_replay = True
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    http, ep = _ConfirmHttp(), _endpoint([_attacker_shape()])
    calls = {"n": 0}

    def get(url, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return SimpleNamespace(
                status_code=200, text='{"id":"/888","name":"VICTIM-NAME"}')
        return SimpleNamespace(
            status_code=200, text='{"id":"/888","name":"ATTACKER-NAME"}')
    http.get = get
    owner = SimpleNamespace(name="owner", tenant="acme",
                            auth_headers={"Cookie": "session=OWNER"})
    victims = [_victim()]
    from main.stages.validation import ProbeControls
    from main.stages.validation.authz import authz_write_replay
    findings = authz_write_replay(
        ep, victims, [owner, _tester()], _owner_headers(),
        EvidenceStore(tmp_path / "proofs"), Metrics(), CoverageTracker(),
        http, {"id"}, orch.cfg, orch.scope,
        ProbeControls.from_orchestrator(orch))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "bola-write"
    assert finding.validation_status == "confirmed"
    assert "verified-effect" in finding.tags
