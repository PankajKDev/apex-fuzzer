"""Login workflows: form login, refresh, MFA checkpoints (agent P2).

Drives login sequences through the browser primitives (goto → fill
credentials → submit → verify), captures the resulting session, and
converts it to request headers. MFA is never bypassed: when a
challenge appears the attempt stops at a persisted MfaCheckpoint for
the operator to complete out-of-band.

Passwords never come from config files — LoginIdentity carries
`password_env`, resolved from the environment at runtime.
"""
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple
from ..browser.workflows import BrowserWorkflow
from ..browser.sessions import (looks_logged_out)
from ..browser.storage import StorageCapture
from ..logging_setup import get_logger
from .sessions import from_browser_session

log = get_logger("auth-login")

MFA_URL_HINTS = ("mfa", "challenge", "verify", "totp", "otp",
                 "two-factor", "2fa", "authenticator")
MFA_HTML_HINTS = ('name="otp"', "name='otp'", 'name="totp"',
                  "name='totp'", 'name="code"', 'autocomplete="one-time-code"')


@dataclass
class LoginIdentity:
    name: str
    username: str = ""
    password_env: str = ""
    roles: List[str] = field(default_factory=list)
    tenant: str = ""

    def resolve_password(self) -> str:
        return os.environ.get(self.password_env, "") if \
            self.password_env else ""


@dataclass
class MfaCheckpoint:
    """Pending manual step: persisted, never auto-completed."""
    identity: str
    url: str
    detail: str = ""
    created_ts: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"identity": self.identity, "url": self.url,
                "detail": self.detail,
                "created_ts": self.created_ts or time.time()}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "MfaCheckpoint":
        return cls(identity=d.get("identity", ""), url=d.get("url", ""),
                   detail=d.get("detail", ""),
                   created_ts=d.get("created_ts", 0.0))

    def save(self, path: Path) -> Path:
        import os
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path


def looks_like_mfa(url: str, html: str) -> bool:
    path = (url or "").lower()
    if any(h in path for h in MFA_URL_HINTS):
        return True
    body = (html or "").lower()
    return any(h in body for h in MFA_HTML_HINTS)


class LoginManager:
    def __init__(self, login_cfg, scope=None, budgets=None,
                 timeout_ms: int = 30000):
        self.cfg = login_cfg
        self.scope = scope
        self.budgets = budgets
        self.timeout_ms = timeout_ms
        self.workflows: Dict[str, BrowserWorkflow] = {}

    def build_workflow(self, login_id: LoginIdentity, password: str,
                       username: str = "") -> BrowserWorkflow:
        """Pure builder: login URL → fill → submit → wait. Testable
        without a browser."""
        cfg = self.cfg
        wf = BrowserWorkflow(f"login-{login_id.name}")
        wf.add("goto", cfg.url, timeout_ms=self.timeout_ms)
        wf.add("fill", f'input[name="{cfg.username_field}"]',
               username or login_id.username)
        wf.add("fill", f'input[name="{cfg.password_field}"]', "•••")
        wf.add("click", cfg.submit)
        if getattr(cfg, "success_url_contains", ""):
            wf.add("wait_url", f"*{cfg.success_url_contains}*")
        elif getattr(cfg, "success_text", ""):
            wf.add("wait_text", cfg.success_text)
        self.workflows[login_id.name] = wf
        # The recorded artifact always masks the password; attempt()
        # executes the same steps with the real secret directly.
        return wf

    def attempt(self, page, context, login_id: LoginIdentity,
                password: str) -> Tuple[str, Any]:
        """Run the login flow. Returns (status, payload):
        ok → AuthSession | mfa → MfaCheckpoint | failed → reason str."""
        from ..browser.actions import fill_form, click
        from ..browser.sessions import SessionManager as _SM
        cfg = self.cfg
        if self.budgets is not None and \
                not self.budgets.consume_test("browser",
                                              f"login::{login_id.name}"):
            return "failed", "browser action budget exhausted"
        self.build_workflow(login_id, password)  # recorded, masked
        try:
            page.goto(cfg.url, timeout=self.timeout_ms)
            filled = fill_form(page, {
                cfg.username_field: login_id.username,
                cfg.password_field: password})
            if filled < 2:
                return "failed", (f"login form fields not found "
                                  f"(filled {filled}/2)")
            page.wait_for_timeout(500)
            if not click(page, cfg.submit):
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    return "failed", "submit control not clickable"
            try:
                page.wait_for_load_state("networkidle",
                                         timeout=self.timeout_ms)
            except Exception:
                pass
            try:
                cur_url = page.url
                html = page.content() or ""
            except Exception as e:
                return "failed", f"post-login read failed: {e}"
        except Exception as e:
            return "failed", f"login navigation failed: {e}"
        if looks_like_mfa(cur_url, html):
            log.warning("login '%s': MFA challenge — manual step "
                        "required, will not bypass", login_id.name)
            return "mfa", MfaCheckpoint(
                identity=login_id.name, url=cur_url,
                detail="multi-factor challenge detected after submit")
        if looks_logged_out(cur_url, html):
            return "failed", (f"still logged out after submit "
                              f"(at {cur_url[:120]})")
        try:
            capture = StorageCapture().capture(context, page)
            browser_sess = _SM().from_capture(
                capture, login_id.name,
                tenant=login_id.tenant)
            session = from_browser_session(
                browser_sess,
                role=",".join(login_id.roles))
            session.created_ts = time.time()
            log.info("login '%s': session minted (%d cookies)",
                     login_id.name, len(session.cookies))
            return "ok", session
        except Exception as e:
            return "failed", f"session capture failed: {e}"
