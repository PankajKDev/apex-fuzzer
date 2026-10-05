"""Automated login: mint sessions for configured login identities."""
from pathlib import Path

from ..logging_setup import get_logger
from ..reporting.metrics import Metrics

log = get_logger("stages-auth")


def login_identities(out_dir: Path, metrics: Metrics, cfg, scope):
    """Mint sessions for login identities lacking headers.

    Only enriches auth contexts that exist by name and have no
    headers yet. MFA stops at a persisted checkpoint for the
    operator — never bypassed, never retried blindly.
    """
    login = cfg.auth.login
    if not login.enabled or not login.url or not login.identities:
        return
    if not scope.is_in_scope(login.url):
        log.warning("login: %s out of scope — skipping", login.url)
        return
    from ..browser.browser import BrowserEngine, playwright_available
    if not playwright_available():
        log.info("login: playwright not installed — skipping")
        return
    from ..auth.workflows import LoginManager, LoginIdentity
    from ..browser.sessions import SessionManager
    mgr = LoginManager(login, scope=scope,
                       timeout_ms=cfg.browser.navigation_timeout_ms)
    by_name = {c.name: c for c in cfg.auth.contexts}
    try:
        with BrowserEngine(
                cfg,
                headless=cfg.browser.headless,
                timeout_ms=cfg.browser.navigation_timeout_ms
                ) as engine:
            for entry in login.identities:
                if entry.name not in by_name:
                    log.debug("login: no auth context named '%s' — "
                              "skipping (contexts are never auto-"
                              "created)", entry.name)
                    continue
                ctx = by_name[entry.name]
                if ctx.headers:
                    continue
                password = LoginIdentity(
                    name=entry.name, username=entry.username,
                    password_env=entry.password_env,
                    roles=list(entry.roles),
                    tenant=entry.tenant).resolve_password()
                if not password:
                    log.warning(
                        "login '%s': %s is empty/unset — skipping",
                        entry.name,
                        entry.password_env or "(no password_env)")
                    continue
                metrics.logins_attempted += 1
                try:
                    bctx = engine.new_context(identity=entry.name)
                    page = bctx.new_page()
                except Exception as e:
                    log.warning("login '%s': context failed: %s",
                                entry.name, e)
                    continue
                try:
                    status, payload = mgr.attempt(
                        page, bctx,
                        LoginIdentity(
                            name=entry.name,
                            username=entry.username,
                            password_env=entry.password_env,
                            roles=list(entry.roles),
                            tenant=entry.tenant),
                        password)
                finally:
                    try:
                        page.close()
                    except Exception:
                        pass
                    try:
                        bctx.close()
                    except Exception:
                        pass
                if status == "ok":
                    ident = payload.to_identity()
                    ctx.headers = dict(ident.auth_headers)
                    ctx.identity = ctx.identity or entry.name
                    if not ctx.roles:
                        ctx.roles = list(entry.roles)
                    if not ctx.tenant:
                        ctx.tenant = entry.tenant
                    metrics.logins_succeeded += 1
                    try:
                        SessionManager(
                            out_dir / "sessions").save(payload)
                    except Exception as e:
                        log.debug("login: session save failed: %s",
                                  e)
                    log.info("login '%s': context enriched "
                             "(%d cookies)", entry.name,
                             len(payload.cookies))
                elif status == "mfa":
                    try:
                        from ..scope import slug_filename
                        payload.save(out_dir /
                                     f"mfa_{slug_filename(entry.name)}.json")
                    except Exception as e:
                        log.debug("login: checkpoint save failed: %s",
                                  e)
                    log.warning(
                        "login '%s': MFA checkpoint at %s — complete "
                        "the challenge manually, then re-run with a "
                        "static session", entry.name, payload.url)
                else:
                    log.warning("login '%s' failed: %s",
                                entry.name, payload)
    except RuntimeError as e:
        log.warning("login unavailable: %s", e)
    except Exception as e:
        log.warning("login engine failed: %s", e, exc_info=True)
