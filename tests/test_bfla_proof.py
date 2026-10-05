"""BFLA state-changing proof: tester shape replay + reader readback.

No network. Fake HTTP clients only. Unlike the BOLA-write replay, an
accepted-but-unproven BFLA replay keeps the sweep candidate standing
(the sweep 200s already show identical treatment) instead of
refuting to inconclusive — only newly-persisted markers confirm.
"""
from types import SimpleNamespace

from main.authorization import write_replay as wr_mod
from main.budgets import BudgetExceeded
from main.config import ScopeConfig
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


def _tester_shape(body="name=LOW-NAME&role=member"):
    return {"identity": "low", "method": "POST",
            "url": "https://example.test/app/updateUser",
            "headers": {"Content-Type":
                        "application/x-www-form-urlencoded"},
            "post_data": body,
            "content_type": "application/x-www-form-urlencoded"}


def _tester():
    return SimpleNamespace(name="low", tenant="acme",
                           auth_headers={"Cookie": "session=LOW"})


def _reader():
    return SimpleNamespace(name="boss", tenant="acme",
                           auth_headers={"Cookie": "session=BOSS"})


def _owner_headers():
    return {"boss": {"Cookie": "session=BOSS"},
            "low": {"Cookie": "session=LOW"}}


class _ConfirmHttp:
    """Baseline without marker; replay accepted; marker persists."""

    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        if len(self.calls) == 1:
            return SimpleNamespace(
                status_code=200,
                text='{"name":"ADMIN-NAME","role":"admin"}')
        return SimpleNamespace(
            status_code=200,
            text='{"name":"LOW-NAME","role":"admin"}')

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return SimpleNamespace(
            status_code=200, text='{"result":"updated"}')


def test_accepted_write_confirmed_by_readback():
    out = wr_mod.prove_bfla(_ConfirmHttp(), _endpoint([_tester_shape()]),
                            "POST", _tester(), _reader(),
                            _owner_headers(), scope=_scope())
    assert out.verdict == "confirmed"
    assert out.readback == "confirmed-persisted"
    assert out.markers_matched == ["name"]
    assert out.replay_accepted is True


def test_clean_readback_keeps_candidate_standing():
    class Http:
        def get(self, url, **kwargs):
            return SimpleNamespace(
                status_code=200,
                text='{"name":"ADMIN-NAME","role":"admin"}')

        def request(self, method, url, **kwargs):
            return SimpleNamespace(
                status_code=200, text='{"result":"updated"}')

    out = wr_mod.prove_bfla(Http(), _endpoint([_tester_shape()]),
                            "POST", _tester(), _reader(),
                            _owner_headers(), scope=_scope())
    # BFLA differs from BOLA-write here: the sweep 200s already prove
    # identical treatment, so an unproven replay stands as a candidate
    # instead of refuting to inconclusive.
    assert out.verdict == "strong_candidate"
    assert out.readback == "no-persistence-observed"
    assert out.replay_accepted is True


def test_denied_replay_stays_inconclusive():
    class Http:
        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=200, text='{"a":1}')

        def request(self, method, url, **kwargs):
            return SimpleNamespace(status_code=403, text="denied")

    out = wr_mod.prove_bfla(Http(), _endpoint([_tester_shape()]),
                            "POST", _tester(), _reader(),
                            _owner_headers(), scope=_scope())
    assert out.verdict == "inconclusive"
    assert out.replay_accepted is False


def test_no_shape_sends_nothing():
    class Http:
        def get(self, *a, **k):
            raise AssertionError("no baseline without a shape")

        def request(self, *a, **k):
            raise AssertionError("must not send")

    ep = _endpoint([{"identity": "boss", "method": "POST",
                     "url": "https://example.test/app/updateUser",
                     "headers": {}, "post_data": "name=x",
                     "content_type":
                     "application/x-www-form-urlencoded"}])
    out = wr_mod.prove_bfla(Http(), ep, "POST", _tester(), _reader(),
                            _owner_headers(), scope=_scope())
    assert out.verdict == "inconclusive"
    assert "no observed" in out.notes


def test_empty_shape_sends_nothing():
    class Http:
        def request(self, *a, **k):
            raise AssertionError("empty shape proves nothing")

        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=200, text="{}")

    ep = _endpoint([{"identity": "low", "method": "POST",
                     "url": "https://example.test/app/updateUser",
                     "headers": {}, "post_data": "",
                     "content_type":
                     "application/x-www-form-urlencoded"}])
    out = wr_mod.prove_bfla(Http(), ep, "POST", _tester(), _reader(),
                            _owner_headers(), scope=_scope())
    assert out.verdict == "inconclusive"
    assert "values" in out.notes


def test_ambiguous_shapes_fail_closed():
    class Http:
        def request(self, *a, **k):
            raise AssertionError("ambiguous must not send")

        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=200, text="{}")

    shapes = [_tester_shape("name=AAA"), _tester_shape("name=BBB")]
    out = wr_mod.prove_bfla(Http(), _endpoint(shapes), "POST",
                            _tester(), _reader(), _owner_headers(),
                            scope=_scope())
    assert out.verdict == "inconclusive"
    assert "ambiguous" in out.notes


def test_get_and_delete_skip_without_sending():
    class Http:
        def request(self, *a, **k):
            raise AssertionError("sweep-only methods must not send")

        def get(self, *a, **k):
            raise AssertionError("skipped proofs read nothing")

    ep = _endpoint([_tester_shape()])
    for method in ("GET", "DELETE"):
        out = wr_mod.prove_bfla(Http(), ep, method, _tester(),
                                _reader(), _owner_headers(),
                                scope=_scope())
        assert out.verdict == "inconclusive"
        assert "skipped" in out.notes


def test_multipart_shape_is_skipped():
    class Http:
        def request(self, *a, **k):
            raise AssertionError("multipart must not send")

        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=200, text="{}")

    ep = _endpoint([{"identity": "low", "method": "POST",
                     "url": "https://example.test/app/updateUser",
                     "headers": {"Content-Type":
                                 "multipart/form-data; boundary=b"},
                     "post_data": "--b\r\nok\r\n--b--\r\n",
                     "content_type": "multipart/form-data; boundary=b"}])
    out = wr_mod.prove_bfla(Http(), ep, "POST", _tester(), _reader(),
                            _owner_headers(), scope=_scope())
    assert out.verdict == "inconclusive"


def test_budget_exhaustion_propagates():
    class Http:
        def get(self, *a, **k):
            raise BudgetExceeded("request budget exhausted")

        def request(self, *a, **k):
            raise AssertionError("must not reach replay")

    try:
        wr_mod.prove_bfla(Http(), _endpoint([_tester_shape()]),
                          "POST", _tester(), _reader(),
                          _owner_headers(), scope=_scope())
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_tester_reader_split_prefers_admin_reader():
    from main.stages.validation.authz import _bfla_tester_reader
    obs = [SimpleNamespace(status=200, identity="boss", role="admin"),
           SimpleNamespace(status=200, identity="low", role="member")]
    tester, reader = _bfla_tester_reader(obs)
    assert tester.identity == "low"
    assert reader.identity == "boss"
    assert _bfla_tester_reader([]) == (None, None)
    denied = [SimpleNamespace(status=403, identity="low", role="")]
    assert _bfla_tester_reader(denied) == (None, None)


def test_tester_reader_prefers_authed_over_anonymous():
    from main.stages.validation.authz import _bfla_tester_reader
    obs = [SimpleNamespace(status=200, identity="anonymous", role=""),
           SimpleNamespace(status=200, identity="low", role="member"),
           SimpleNamespace(status=200, identity="boss", role="admin")]
    tester, reader = _bfla_tester_reader(obs)
    assert tester.identity == "low"
    assert reader.identity == "boss"


def test_attempt_helper_maps_confirmation_to_finding_fields():
    from main.stages.validation import ProbeControls
    from main.stages.validation.authz import attempt_bfla_proof
    cfg = SimpleNamespace(scan=SimpleNamespace(http_timeout=10))
    obs = [SimpleNamespace(status=200, identity="low", role="member"),
           SimpleNamespace(status=200, identity="boss", role="admin")]
    proof, updates = attempt_bfla_proof(
        _endpoint([_tester_shape()]), "POST", obs,
        [_tester(), _reader()], _owner_headers(), _ConfirmHttp(),
        cfg, _scope(), ProbeControls())
    assert proof is not None and proof.verdict == "confirmed"
    assert updates["status"] == "confirmed"
    assert updates["confidence"] == "confirmed"
    assert updates["extra_tags"] == ["verified-effect"]
    assert updates["suffix"] == " [verified effect]"


def test_attempt_helper_leaves_unproven_candidate_untouched():
    from main.stages.validation import ProbeControls
    from main.stages.validation.authz import attempt_bfla_proof

    class Http:
        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=200, text='{"a":1}')

        def request(self, method, url, **kwargs):
            return SimpleNamespace(status_code=403, text="denied")

    cfg = SimpleNamespace(scan=SimpleNamespace(http_timeout=10))
    obs = [SimpleNamespace(status=200, identity="low", role="member"),
           SimpleNamespace(status=200, identity="boss", role="admin")]
    proof, updates = attempt_bfla_proof(
        _endpoint([_tester_shape()]), "POST", obs,
        [_tester(), _reader()], _owner_headers(), Http(),
        cfg, _scope(), ProbeControls())
    assert proof is not None and proof.verdict == "inconclusive"
    assert updates == {}


def test_plan_accounts_bfla_proofs():
    from main.safety.preflight import plan_authz_matrix
    base = plan_authz_matrix(2, 3, 5, 3)
    assert base.total == 6 + 24 + 30
    extended = plan_authz_matrix(2, 3, 5, 3, bfla_proofs=4)
    assert extended.total == base.total + 12


def test_read_url_prefers_reader_get_shape():
    reader_get = {"identity": "boss", "method": "GET",
                  "url": ("https://example.test/app/updateUser"
                          "?view=full"),
                  "headers": {}, "post_data": "",
                  "content_type": ""}
    ep = _endpoint([_tester_shape(), reader_get])
    url = wr_mod._bfla_read_url(ep, "boss")
    assert url is not None and "view=full" in url
