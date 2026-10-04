"""Public archive recon must not disclose local lab targets."""
from apex_fuzzer.orchestrator import _is_public_archive_target
from apex_fuzzer.profiles import get


def test_public_archive_lookups_are_limited_to_public_targets():
    assert not _is_public_archive_target("http://localhost:8765")
    assert not _is_public_archive_target("http://lab.localhost:8765")
    assert not _is_public_archive_target("http://127.0.0.1:8765")
    assert not _is_public_archive_target("http://10.0.0.4:8080")
    assert _is_public_archive_target("https://example.com")
    assert _is_public_archive_target("https://8.8.8.8")


def test_passive_profile_skips_nuclei_validation_and_takeover():
    profile = get("passive")
    assert not profile.run_nuclei
    assert not profile.run_validation
    assert not profile.run_subzy
    assert not profile.run_tko
    assert not profile.oast
