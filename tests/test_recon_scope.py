"""Public archive recon must not disclose local lab targets."""
from main.models import Endpoint
from main.profiles import get
from main.stages.recon import harvest_api_specs, is_public_archive_target


def test_api_spec_enriches_existing_endpoint(monkeypatch, tmp_path):
    import main.stages.recon as recon_mod
    spec = {"base": "https://example.test",
            "endpoints": [{
                "path": "/api/update", "method": "POST",
                "operation_id": "", "summary": "", "description": "",
                "tags": [],
                "request_content_types": ["application/json"],
                "parameters": [{"name": "name", "in": "body"}]}]}
    monkeypatch.setattr(
        recon_mod.spec_mod, "discover",
        lambda client, base_url, timeout: [spec])
    ep = Endpoint(url="https://example.test/api/update",
                  normalized_url="https://example.test/api/update",
                  host="example.test", path="/api/update",
                  method="GET", endpoint_type="api")
    harvest_api_specs(object(), "https://example.test", [ep],
                      tmp_path, 10, _scope())
    assert "application/json" in ep.request_content_types
    assert [p.name for p in ep.body_parameters] == ["name"]


def _scope():
    from main.config import ScopeConfig
    from main.scope import Scope
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def test_public_archive_lookups_are_limited_to_public_targets():
    assert not is_public_archive_target("http://localhost:8765")
    assert not is_public_archive_target("http://lab.localhost:8765")
    assert not is_public_archive_target("http://127.0.0.1:8765")
    assert not is_public_archive_target("http://10.0.0.4:8080")
    assert is_public_archive_target("https://example.com")
    assert is_public_archive_target("https://8.8.8.8")


def test_passive_profile_skips_nuclei_validation_and_takeover():
    profile = get("passive")
    assert not profile.run_nuclei
    assert not profile.run_validation
    assert not profile.run_subzy
    assert not profile.run_tko
    assert not profile.oast
