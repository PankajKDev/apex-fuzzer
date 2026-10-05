"""Scope enforcement."""
from pathlib import Path
from urllib.parse import urlparse
from .config import ScopeConfig
from .logging_setup import get_logger

log = get_logger("scope")


def target_hostname(target: str) -> str:
    """Return the hostname from a target URL, excluding its port."""
    value = (target if "://" in (target or "")
             else f"http://{target or ''}")
    try:
        return (urlparse(value).hostname or "").lower()
    except ValueError:
        return ""


def slug_host(host: str) -> str:
    """Make operator/recon-derived host text safe as one path part.

    Dots, colons (host:port), dashes, and underscores survive so
    output dirs stay readable; everything else becomes ``_``.
    Exact ``.``/``..`` (directory escape) and empties fall back to
    ``target``. Always apply before joining an output root.
    """
    import re
    text = re.sub(r"[^A-Za-z0-9.\-_:]", "_", (host or "").strip())
    if text in ("", ".", ".."):
        return "target"
    return text[:255]


def slug_filename(name: str) -> str:
    """Make config-derived names safe as one filename part."""
    import re
    text = re.sub(r"[^A-Za-z0-9.\-_]", "_", (name or "").strip())
    if text in ("", ".", ".."):
        return "unnamed"
    return text[:64]


class Scope:
    def __init__(self, cfg: ScopeConfig):
        self.cfg = cfg
        self._excluded_hosts = {h.lower() for h in cfg.excluded_hosts}
        self._excluded_paths = list(cfg.excluded_paths)

    @staticmethod
    def _allowed_host(host: str, allowed: str,
                      allow_subdomains: bool) -> bool:
        rule = allowed.lower().strip()
        # leading-dot and wildcard forms both mean "this domain and
        # (when subdomains are allowed) everything under it"
        if rule.startswith("*."):
            rule = rule[2:]
        rule = rule.lstrip(".")
        if not rule or "*" in rule:
            return False
        if host == rule:
            return True
        return bool(allow_subdomains and host.endswith("." + rule))

    @staticmethod
    def _url_port(parsed) -> int:
        try:
            if parsed.port is not None:
                return int(parsed.port)
        except (TypeError, ValueError):
            pass
        return 443 if parsed.scheme == "https" else 80

    def check(self, url: str) -> tuple:
        """Scope decision with a stable audit reason.

        Reasons: allowed, unsupported_scheme, out_of_scope_domain,
        excluded_host, excluded_path, disallowed_port.
        """
        if not url:
            return False, "out_of_scope_domain"
        try:
            p = urlparse(url)
        except ValueError:
            return False, "out_of_scope_domain"
        if p.scheme not in ("http", "https"):
            return False, "unsupported_scheme"
        host = (p.hostname or "").lower()
        if not host:
            return False, "out_of_scope_domain"
        if host in self._excluded_hosts:
            return False, "excluded_host"
        for path in self._excluded_paths:
            if p.path.startswith(path):
                return False, "excluded_path"
        allowed_ports = list(getattr(self.cfg, "allowed_ports", None)
                             or [])
        if allowed_ports and self._url_port(p) not in allowed_ports:
            return False, "disallowed_port"
        if not self.cfg.allowed_domains:
            return True, "allowed"
        for allowed in self.cfg.allowed_domains:
            if self._allowed_host(host, str(allowed),
                                  self.cfg.allow_subdomains):
                return True, "allowed"
        return False, "out_of_scope_domain"

    def is_in_scope(self, url: str) -> bool:
        allowed, _ = self.check(url)
        return allowed

    def active_test_allowed(self, url: str) -> bool:
        if not self.is_in_scope(url):
            return False
        try:
            path = urlparse(url).path.lower()
        except ValueError:
            return False
        ext = Path(path).suffix.lstrip(".").lower()
        if ext and ext in {e.lower() for e in
                           self.cfg.active_test_exclude_exts}:
            return False
        return True
