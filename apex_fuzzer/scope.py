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


class Scope:
    def __init__(self, cfg: ScopeConfig):
        self.cfg = cfg
        self._excluded_hosts = {h.lower() for h in cfg.excluded_hosts}
        self._excluded_paths = list(cfg.excluded_paths)

    def is_in_scope(self, url: str) -> bool:
        if not url:
            return False
        try:
            p = urlparse(url)
        except ValueError:
            return False
        if p.scheme not in ("http", "https"):
            return False
        host = (p.hostname or "").lower()
        if not host:
            return False
        if host in self._excluded_hosts:
            return False
        for path in self._excluded_paths:
            if p.path.startswith(path):
                return False
        if not self.cfg.allowed_domains:
            return True
        for allowed in self.cfg.allowed_domains:
            allowed = allowed.lower().lstrip(".")
            if host == allowed:
                return True
            if self.cfg.allow_subdomains and host.endswith("." + allowed):
                return True
        return False

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
