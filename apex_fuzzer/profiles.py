"""Testing profiles (spec §34)."""
from dataclasses import dataclass


@dataclass
class Profile:
    name: str
    run_httpx: bool = True
    run_subzy: bool = True
    run_nuclei: bool = True
    run_validation: bool = False
    run_ai: bool = False
    js_analysis: bool = True
    api_specs: bool = True
    robots: bool = True
    differential: bool = False
    # Arjun active hidden-parameter mining (spec §1)
    param_mining: bool = True
    # Interactsh OAST sweep for blind SSRF (spec §3)
    oast: bool = False
    # tko-subs confirmed subdomain takeover (spec §10)
    run_tko: bool = False
    # cross-user swap + per-method authz matrix (bounty items #1–2)
    authz_matrix: bool = False
    # stored-XSS correlation — persists canary data (bounty item #3)
    second_order: bool = False


PROFILES = {
    "passive": Profile(
        name="passive", run_nuclei=False, run_validation=False,
        run_ai=False, differential=False, param_mining=False,
        oast=False,
    ),
    "standard": Profile(name="standard"),
    "deep": Profile(
        name="deep", differential=True, js_analysis=True,
        oast=True, run_tko=True, authz_matrix=True, second_order=True,
    ),
    "api": Profile(
        name="api", robots=False, differential=True, oast=True,
        authz_matrix=True,
    ),
    "authenticated": Profile(
        name="authenticated", differential=True, oast=True,
        authz_matrix=True,
    ),
    "validation": Profile(
        name="validation", run_validation=True, oast=True,
        second_order=True,
    ),
}


def get(name: str) -> Profile:
    return PROFILES.get(name, PROFILES["standard"])
