"""High-impact authorization model (Milestone 1, strict mode only).

Default scans are UNCHANGED: these gates engage only when strict mode
is on (`--strict` / `safety.strict`). Then every enabled stateful /
burst / claiming module must satisfy ALL of:

- an authorization reference is recorded,
- the operator acknowledged state changes (`--ack-state-change`),
- the target matches the approved allowlist (domains, or literal-IP
  CIDRs — hostnames are never DNS-resolved for matching),
- the current time falls inside the validity window (empty bounds =
  unbounded; documented, deliberate),
- the module key is allowlisted.

Failure raises AuthorizationRefused (exit code 2) listing every
unmet condition. Reports carry the metadata block (reference string
only — never document content, never secrets).
"""

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_REFUSED = 2

GATED_MODULES = ("business_logic", "race", "second_order",
                 "authz_matrix", "takeover_claim", "login")

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse


class AuthorizationRefused(Exception):
    """Raised pre-network when strict-mode gates fail. Carries reasons."""

    def __init__(self, reasons: List[str]):
        self.reasons = list(reasons)
        super().__init__("; ".join(reasons))


@dataclass
class Authorization:
    reference: str = ""
    approved_domains: List[str] = field(default_factory=list)
    approved_cidrs: List[str] = field(default_factory=list)
    valid_from: str = ""
    valid_until: str = ""
    allowed_modules: List[str] = field(default_factory=list)
    allow_state_change: bool = False

    @classmethod
    def from_safety_cfg(cls, cfg) -> "Authorization":
        s = cfg.safety
        return cls(
            reference=str(getattr(s, "authorization_ref", "") or ""),
            approved_domains=[str(d).lower().lstrip(".") for d in
                              (getattr(s, "approved_domains", None) or [])],
            approved_cidrs=[str(c) for c in
                            (getattr(s, "approved_cidrs", None) or [])],
            valid_from=str(getattr(s, "valid_from", "") or ""),
            valid_until=str(getattr(s, "valid_until", "") or ""),
            allowed_modules=[str(m) for m in
                             (getattr(s, "allowed_modules", None) or [])],
            allow_state_change=bool(
                getattr(s, "allow_state_change", False)))

    def _target_host(self, target: str) -> str:
        try:
            parsed = urlparse(target if "://" in target
                              else f"https://{target}")
            return (parsed.hostname or "").lower()
        except Exception:
            return ""

    def target_allowed(self, target: str) -> bool:
        host = self._target_host(target)
        if not host:
            return False
        for domain in self.approved_domains:
            if host == domain or host.endswith("." + domain):
                return True
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False  # hostname, no domain match → denied
        for cidr in self.approved_cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def time_valid(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)

        def _parse(value: str):
            if not value:
                return None
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return dt if dt.tzinfo else dt.replace(
                    tzinfo=timezone.utc)
            except ValueError:
                return False

        start, end = _parse(self.valid_from), _parse(self.valid_until)
        if start is False or end is False:
            return False  # malformed bounds fail closed
        if start is not None and now < start:
            return False
        if end is not None and now > end:
            return False
        return True

    def check(self, target: str, modules: List[str]) -> List[str]:
        """Unmet conditions for running modules on target (empty = ok)."""
        gated = [m for m in modules if m in GATED_MODULES]
        if not gated:
            return []
        reasons: List[str] = []
        if not self.reference:
            reasons.append("no authorization reference "
                           "(safety.authorization_ref / --auth-ref)")
        if not self.allow_state_change:
            reasons.append("state changes not acknowledged "
                           "(--ack-state-change)")
        if not self.target_allowed(target):
            reasons.append(f"target not allowlisted: {target}")
        if not self.time_valid():
            reasons.append("outside authorization validity window")
        missing = [m for m in gated if m not in self.allowed_modules]
        if missing:
            reasons.append("modules not allowlisted: " +
                           ", ".join(sorted(missing)))
        return reasons

    def describe(self) -> dict:
        return {"reference": self.reference,
                "approved_domains": list(self.approved_domains),
                "approved_cidrs": list(self.approved_cidrs),
                "valid_from": self.valid_from,
                "valid_until": self.valid_until,
                "allowed_modules": list(self.allowed_modules),
                "allow_state_change": self.allow_state_change}
