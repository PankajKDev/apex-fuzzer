"""Browser proof that a state-changing request executes cross-site.

A null-origin attacker page (fulfilled in-route, never hosted) auto-
submits the tokenless form shape with the victim's session, exactly
like a classic CSRF drop. The route guard records whether the victim
cookie left the browser and what status the server returned, then
fulfills the real response so navigation completes. Acceptance (2xx
with cookie) proves cross-site execution; the state change itself
still needs app-specific readback, so this never confirms impact.
"""
from __future__ import annotations

import html as _htmllib
import json
import time
from typing import Any, Dict
from urllib.parse import urlsplit

from ..browser.browser import BrowserEngine
from .cors_browser import _origin, _storage_state

_ATTACK_HOST = "apex-csrf.invalid"

_MAX_TARGET_REQUESTS = 3


def _attack_url() -> str:
    return f"https://{_ATTACK_HOST}/"


def _form_page(target_url: str, method: str,
               fields: Dict[str, str]) -> str:
    inputs = "".join(
        f'<input type="hidden" name="{_htmllib.escape(k, quote=True)}" '
        f'value="{_htmllib.escape(v, quote=True)}">'
        for k, v in fields.items())
    return (
        "<!doctype html><meta charset=utf-8><title>csrf check</title>"
        f"<form method={method} action={json.dumps(target_url)}>"
        f"{inputs}</form>"
        "<script>document.forms[0].submit()</script>")


def prove_csrf_execution(target_url: str, method: str,
                         fields: Dict[str, str], identity: Any,
                         cfg, timeout_ms: int = 10000) -> Dict[str, Any]:
    """Submit the form shape cross-site with the victim session.

    Returns executed | denied | inconclusive | unavailable (see
    module docstring for what each means).
    """
    method = (method or "POST").upper()
    if method not in ("GET", "POST"):
        return {"status": "inconclusive",
                "reason": f"no native cross-site vector for {method}"}
    target_origin = _origin(target_url)
    if target_origin is None:
        return {"status": "inconclusive",
                "reason": "target is not a plain http(s) URL"}
    try:
        state = _storage_state(identity, target_url)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"status": "unavailable",
                "reason": f"browser credentials unavailable: {exc}"[:300]}

    timeout_ms = max(1000, min(15000, int(timeout_ms)))
    engine = BrowserEngine(
        cfg, headless=getattr(cfg.browser, "headless", True),
        timeout_ms=timeout_ms)
    context = None
    try:
        engine.start()
        context = engine.new_context(
            storage_state=state, identity=str(getattr(identity, "name", "")),
            ignore_https_errors=True, service_workers="block")
        attack_url = _attack_url()
        seen = {"cookie": False, "status": 0, "count": 0, "failed": ""}
        browser_errors = []

        def guard(route):
            request = route.request
            if (request.url == attack_url and
                    request.resource_type == "document"):
                route.fulfill(status=200, content_type="text/html",
                              body=_form_page(target_url, method, fields))
                return
            if (_origin(request.url) == target_origin and
                    request.method == method):
                seen["count"] += 1
                if seen["count"] > _MAX_TARGET_REQUESTS:
                    route.abort()
                    return
                seen["cookie"] = seen["cookie"] or bool(
                    request.headers.get("cookie"))
                route.continue_()
                return
            route.abort()

        def on_response(response):
            try:
                if (_origin(response.url) == target_origin and
                        response.request.method == method):
                    seen["status"] = int(response.status or 0)
            except Exception:
                pass

        context.route("**/*", guard)
        page = context.new_page()
        page.on("response", on_response)
        page.on("requestfailed", lambda request: browser_errors.append(
            f"{request.method} {urlsplit(request.url).path}: "
            f"{request.failure or 'request failed'}"[:240]))
        page.goto(attack_url, wait_until="domcontentloaded",
                  timeout=timeout_ms)
        deadline = time.monotonic() + timeout_ms / 1000.0
        while seen["count"] == 0 and time.monotonic() < deadline:
            time.sleep(0.1)
        if seen["count"] == 0:
            return {"status": "inconclusive",
                    "cookie_sent": False,
                    "request_count": 0,
                    "browser": "chromium",
                    "reason": "cross-site form did not submit",
                    "browser_error": (browser_errors[-1]
                                      if browser_errors else "")}
        # Give the continued request a moment to complete.
        deadline = time.monotonic() + 5.0
        while seen["status"] == 0 and time.monotonic() < deadline:
            time.sleep(0.1)
        if seen["cookie"] and 200 <= seen["status"] < 300:
            return {"status": "executed",
                    "cookie_sent": True,
                    "response_status": seen["status"],
                    "request_count": seen["count"],
                    "browser": "chromium",
                    "reason": "cross-site request executed with the "
                              "victim session (server accepted 2xx)"}
        return {"status": "denied",
                "cookie_sent": seen["cookie"],
                "response_status": seen["status"],
                "request_count": seen["count"],
                "browser": "chromium",
                "reason": "cross-site request did not execute with "
                          "effect (denied or cookieless)",
                "browser_error": (browser_errors[-1]
                                  if browser_errors else "")}
    except Exception as exc:
        return {"status": "unavailable",
                "reason": f"browser verification failed: "
                          f"{type(exc).__name__}: {exc}"[:300]}
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        engine.stop()
