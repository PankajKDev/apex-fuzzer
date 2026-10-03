"""Coverage metrics."""
from dataclasses import dataclass, field, asdict
from typing import Dict, Any
import json


@dataclass
class Metrics:
    urls_discovered: int = 0
    unique_endpoints: int = 0
    parameters_discovered: int = 0
    js_files_analyzed: int = 0
    source_maps_found: int = 0
    technologies_detected: int = 0
    live_hosts: int = 0
    nuclei_findings: int = 0
    nuclei_findings_after_dedup: int = 0
    validation_candidates: int = 0
    validated_confirmed: int = 0
    false_positives: int = 0
    hypotheses_generated: int = 0
    scan_duration_seconds: float = 0.0
    stage_durations: Dict[str, float] = field(default_factory=dict)
    # v5.2 — new stages
    arjun_params_found: int = 0
    arjun_endpoints_mined: int = 0
    differential_probes: int = 0
    differential_candidates: int = 0
    oast_endpoints_probed: int = 0
    oast_confirmed: int = 0
    takeover_confirmed: int = 0
    hypotheses_validated: int = 0
    waf_detected: str = ""
    # Phase 1 — application-aware coverage (§44)
    resources_discovered: int = 0
    identities_tested: int = 0
    roles_tested: int = 0
    tenants_tested: int = 0
    authorization_tests: int = 0
    authorization_confirmed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def write(self, path):
        path.write_text(json.dumps(self.to_dict(), indent=2))
