"""Mass assignment: privileged fields on the tester's OWN object.

No network. Fake HTTP clients only. The probe value is an inert
marker, never a real privilege; persistence proves binder
acceptance, never privilege impact (stays candidate, like swaps).
"""
from types import SimpleNamespace

from main.authorization import write_replay as wr_mod
from main.budgets import BudgetExceeded
from main.config import Config, ScopeConfig
from main.models import Endpoint
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.scope import Scope
from main.validation.evidence import EvidenceStore


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _endpoint(shapes):
    ep = Endpoint(url="https://example.test/app/profile",
                  normalized_url="https://example.test/app/profile",
                  method="POST", host="example.test",
                  path="/app/profile")
    ep.observed_requests = shapes
    return ep


def _tester():
    return SimpleNamespace(name="low", tenant="acme",
                           auth_headers={"Cookie": "session=LOW"})


def _owner_headers():
    return {"low": {"Cookie": "session=LOW"}}


def _json_shape(body='{"name":"low-user"}'):
    return {"identity": "low", "method": "POST",
            "url": "https://example.test/app/profile",
            "headers": {"Content-Type": "application/json"},
            "post_data": body, "content_type": "application/json"}


class _PersistHttp:
    """Own-object read; replay accepted; probe value persists."""

    def __init__(self):
        self.persisted = False

    def get(self, url, **kwargs):
        if self.persisted:
            return SimpleNamespace(
                status_code=200,
                text='{"name":"low-user","role":"apex-mass-probe"}')
        return SimpleNamespace(
            status_code=200, text='{"name":"low-user"}')

    def request(self, method, url, **kwargs):
        import json as _json
        body = _json.loads(kwargs.get("data") or "{}")
        if body.get("role") == "apex-mass-probe":
            self.persisted = True
        return SimpleNamespace(status_code=200, text='{"ok":true}')


def test_persisted_field_is_candidate():
    out = wr_mod.replay_mass_assignment(
        _PersistHttp(), _endpoint([_json_shape()]), _tester(),
        _owner_headers(), scope=_scope())
    assert len(out) == 1
    assert out[0].verdict == "strong_candidate"
    assert out[0].field == "role"
    assert out[0].readback == "confirmed-persisted"
    assert out[0].replay_accepted is True


def test_accepted_without_persistence_is_inconclusive():
    class Http:
        def get(self, url, **kwargs):
            return SimpleNamespace(
                status_code=200, text='{"name":"low-user"}')

        def request(self, method, url, **kwargs):
            return SimpleNamespace(status_code=200, text='{"ok":true}')

    out = wr_mod.replay_mass_assignment(
        Http(), _endpoint([_json_shape()]), _tester(),
        _owner_headers(), scope=_scope())
    assert all(r.verdict == "inconclusive" for r in out)


def test_denied_replay_is_genuine_negative():
    class Http:
        def get(self, url, **kwargs):
            return SimpleNamespace(
                status_code=200, text='{"name":"low-user"}')

        def request(self, method, url, **kwargs):
            return SimpleNamespace(status_code=403, text="denied")

    out = wr_mod.replay_mass_assignment(
        Http(), _endpoint([_json_shape()]), _tester(),
        _owner_headers(), scope=_scope())
    assert all(r.verdict == "tested_negative" for r in out)


def test_no_shape_sends_nothing():
    class Http:
        def get(self, *a, **k):
            raise AssertionError("no baseline without a shape")

        def request(self, *a, **k):
            raise AssertionError("must not send")

    out = wr_mod.replay_mass_assignment(
        Http(), _endpoint([]), _tester(), _owner_headers(),
        scope=_scope())
    assert out[0].verdict == "inconclusive"
    assert "no observed" in out[0].notes


def test_already_bound_field_is_skipped():
    class Http:
        def get(self, url, **kwargs):
            return SimpleNamespace(
                status_code=200, text='{"name":"low-user"}')

        def request(self, *a, **k):
            raise AssertionError("bound field proves nothing")

    shape = _json_shape('{"name":"low-user","role":"user"}')
    out = wr_mod.replay_mass_assignment(
        Http(), _endpoint([shape]), _tester(), _owner_headers(),
        scope=_scope(), fields=("role",))
    assert out[0].verdict == "inconclusive"
    assert "already bound" in out[0].notes


def test_form_shapes_accept_extra_fields():
    class Http:
        def __init__(self):
            self.seen = ""

        def get(self, url, **kwargs):
            return SimpleNamespace(
                status_code=200, text='{"name":"low-user"}')

        def request(self, method, url, **kwargs):
            self.seen = str(kwargs.get("data") or "")
            return SimpleNamespace(status_code=200, text='{"ok":true}')

    http = Http()
    shape = {"identity": "low", "method": "POST",
             "url": "https://example.test/app/profile",
             "headers": {"Content-Type":
                         "application/x-www-form-urlencoded"},
             "post_data": "name=low-user",
             "content_type": "application/x-www-form-urlencoded"}
    out = wr_mod.replay_mass_assignment(
        http, _endpoint([shape]), _tester(), _owner_headers(),
        scope=_scope(), fields=("role",))
    assert "role=apex-mass-probe" in http.seen
    assert out[0].verdict == "inconclusive"


def test_budget_propagates():
    class Http:
        def get(self, *a, **k):
            raise BudgetExceeded("spent")

        def request(self, *a, **k):
            raise AssertionError("must not reach replay")

    try:
        wr_mod.replay_mass_assignment(
            Http(), _endpoint([_json_shape()]), _tester(),
            _owner_headers(), scope=_scope())
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_hook_emits_mass_assignment_finding(tmp_path):
    from main.stages.validation.authz import authz_mass_assignment

    cfg = Config()
    tester = SimpleNamespace(name="low", tenant="acme",
                             auth_headers={"Cookie": "session=LOW"})
    out = authz_mass_assignment(
        _endpoint([_json_shape()]), [tester], _owner_headers(),
        EvidenceStore(tmp_path / "p"), Metrics(), CoverageTracker(),
        _PersistHttp(), cfg, _scope())
    assert len(out) == 1
    assert out[0].source == "mass-assignment"
    assert out[0].validation_status == "strong_candidate"
    assert "verified-effect" not in out[0].tags


def test_reviews_map_mass_assignment_findings():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="mass-assignment",
                tags=["mass_assignment"])) == "mass_assignment"


def test_plan_accounts_mass_assignments():
    from main.safety.preflight import plan_authz_matrix
    base = plan_authz_matrix(2, 3, 5, 3)
    assert base.total == 6 + 24 + 30
    extended = plan_authz_matrix(2, 3, 5, 3, mass_assignments=2)
    assert extended.total == base.total + 10
