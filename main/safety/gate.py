"""Centralized scope gate (default-deny).

Call-site checks (``Scope.is_in_scope`` / ``active_test_allowed``) are
scattered across the orchestrator and every probe. This module is the
single pure decision point the lowest shared HTTP layer will consult:

  scheme -> scope -> DNS/IP policy -> state-change policy

Pure: no network except through the injected resolver. The production
resolver uses ``socket.getaddrinfo``; tests inject fakes.
"""
import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, List, Optional
from urllib.parse import urlsplit, urljoin
from ..budgets import BudgetExceeded


# Stable audit reasons (run DB / logs). Keep additive, never rename.
REASON_ALLOWED = "allowed"
REASON_UNSUPPORTED_SCHEME = "unsupported_scheme"
REASON_OUT_OF_SCOPE = "out_of_scope"
REASON_ACTIVE_TEST_EXCLUDED = "active_test_excluded"
REASON_DNS_FAILURE = "dns_failure"
REASON_BLOCKED_IP_RANGE = "blocked_ip_range"
REASON_STATE_CHANGE_DISABLED = "state_change_disabled"


def is_non_public_ip(ip_str: str) -> bool:
    """True when an IP literal is not globally routable.

    Covers private, loopback, link-local (incl. cloud metadata
    169.254.169.254), multicast, reserved, and unspecified addresses.
    Unparseable input fails closed (treated as non-public).
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True
    # is_global alone is version-dependent (e.g. multicast reports
    # global on some interpreters), so test the concrete properties.
    return bool(not ip.is_global or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified or ip.is_loopback
                or ip.is_link_local or ip.is_private)


class ScopeRefused(BudgetExceeded):
    """Raised when the default-deny gate blocks an outbound request.

    Deliberately a ``BudgetExceeded`` subclass: every probing loop
    already treats that as BLOCKED coverage (never a negative), so a
    denied request — which likewise never ran — propagates correctly
    through all 50+ existing handlers with no per-site edits. The
    ``reason`` attribute and the ``scope_denials`` audit trail keep
    the distinction queryable. Carries the denied ``url``.
    """

    def __init__(self, reason: str, url: str):
        super().__init__(f"scope gate refused {url}: {reason}")
        self.reason = reason
        self.url = url


def _cidr_approved(ip_str: str, approved_cidrs) -> bool:
    """True when an IP literal falls inside an operator-approved CIDR."""
    for cidr in approved_cidrs or ():
        try:
            if ipaddress.ip_address(ip_str.strip()) in \
                    ipaddress.ip_network(str(cidr).strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


class SystemResolver:
    """DNS resolver used in production (getaddrinfo, all families)."""

    def resolve(self, hostname: str) -> List[str]:
        infos = socket.getaddrinfo(hostname, None)
        ips: List[str] = []
        for info in infos:
            try:
                ips.append(str(info[4][0]))
            except (IndexError, TypeError):
                continue
        # dedupe, stable order
        seen = set()
        out = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out


@dataclass
class GateDecision:
    allowed: bool
    reason: str
    ips: Optional[List[str]] = None

    def __post_init__(self):
        if self.ips is None:
            self.ips = []


def can_send(url: str,
             scope,
             resolver=None,
             method: str = "GET",
             active_test: bool = False,
             is_state_changing: bool = False,
             allow_private_targets: bool = False,
             allow_state_change: bool = False,
             approved_cidrs=()) -> GateDecision:
    """Default-deny gate for one outbound request.

    Order: scheme -> scope -> DNS/IP -> state-change. First denial wins
    so audit reasons stay unambiguous. IPs inside ``approved_cidrs``
    bypass the private-range block (explicit operator allowlist).
    """
    _ = method  # reserved: scope rules may become method-aware later
    try:
        parsed = urlsplit(url or "")
    except ValueError:
        return GateDecision(False, REASON_OUT_OF_SCOPE)
    if parsed.scheme not in ("http", "https"):
        return GateDecision(False, REASON_UNSUPPORTED_SCHEME)
    host = parsed.hostname or ""
    if not host:
        return GateDecision(False, REASON_OUT_OF_SCOPE)
    if scope is not None:
        if not scope.is_in_scope(url):
            return GateDecision(False, REASON_OUT_OF_SCOPE)
        if active_test and not scope.active_test_allowed(url):
            return GateDecision(False, REASON_ACTIVE_TEST_EXCLUDED)
    if resolver is not None:
        resolve = getattr(resolver, "resolve", None)
    else:
        resolve = SystemResolver().resolve
    if not callable(resolve):
        return GateDecision(False, REASON_DNS_FAILURE)
    try:
        ips = [str(ip) for ip in resolve(host)]
    except Exception:
        return GateDecision(False, REASON_DNS_FAILURE)
    if not ips:
        return GateDecision(False, REASON_DNS_FAILURE)
    if not allow_private_targets and any(
            is_non_public_ip(ip) and not _cidr_approved(ip, approved_cidrs)
            for ip in ips):
        return GateDecision(False, REASON_BLOCKED_IP_RANGE, ips)
    if is_state_changing and not allow_state_change:
        return GateDecision(False, REASON_STATE_CHANGE_DISABLED, ips)
    return GateDecision(True, REASON_ALLOWED, ips)


def check_redirect(current_url: str,
                   location: str,
                   scope,
                   resolver=None,
                   allow_private_targets: bool = False,
                   approved_cidrs=()) -> GateDecision:
    """Re-check scope/DNS/IP for one redirect hop (never auto-follow).

    Relative ``Location`` values resolve against ``current_url``; the
    destination goes through the same default-deny gate as a fresh
    discovery read (not an active test).
    """
    if not location:
        return GateDecision(False, REASON_OUT_OF_SCOPE)
    target = urljoin(current_url or "", location)
    return can_send(target, scope, resolver,
                    allow_private_targets=allow_private_targets,
                    approved_cidrs=approved_cidrs)


# Type alias for the resolver callable style (host -> [ips]).
ResolverFn = Callable[[str], List[str]]
