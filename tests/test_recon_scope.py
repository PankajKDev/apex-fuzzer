"""Public archive recon must not disclose local lab targets."""
from main.profiles import get
from main.stages.recon import is_public_archive_target


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
