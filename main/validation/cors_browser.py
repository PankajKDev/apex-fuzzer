"""Browser proof that a cookie-authenticated CORS response is readable."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlsplit

from ..browser.browser import BrowserEngine


_MAX_STORAGE_STATE_BYTES = 4 * 1024 * 1024
_MAX_TARGET_REQUESTS = 5


def _origin(value: str):
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        return parts.scheme.lower(), parts.hostname.lower(), port
    except (TypeError, ValueError):
        return None


def _storage_state(identity: Any, target_url: str) -> Dict[str, Any]:
    state_path = str(getattr(identity, "storage_state", "") or "").strip()
    if state_path:
        path = Path(state_path)
        if path.stat().st_size > _MAX_STORAGE_STATE_BYTES:
            raise ValueError("browser storage state exceeds 4 MiB")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("browser storage state must be a JSON object")
        return value

    headers = getattr(identity, "auth_headers", {}) or {}
    cookie_header = next((str(value) for key, value in headers.items()
                          if str(key).lower() == "cookie"), "")
    parts = urlsplit(target_url)
    cookies = []
    for field in cookie_header.split(";"):
        name, separator, value = field.strip().partition("=")
        if not separator or not name or any(c in name for c in "\r\n;="):
            continue
        cookies.append({
            "name": name,
            "value": value,
            "domain": parts.hostname,
            "path": "/",
            "httpOnly": True,
            "secure": parts.scheme.lower() == "https",
            # Header-only sessions lack SameSite metadata. Lax is Chromium's
            # conservative default and prevents optimistic cross-site proof.
            "sameSite": "Lax",
        })
    if not cookies:
        raise ValueError("identity has no usable cookie credentials")
    return {"cookies": cookies, "origins": []}


def confirm_cors_readability(finding, identity: Any, cfg,
                             timeout_ms: int = 10000) -> Dict[str, Any]:
    """Use Chromium to fetch the candidate endpoint from its probed Origin.

    Only the exact probe origin and target origin are reachable. The browser
    can issue at most five GET requests; all other traffic is aborted. The
    response body is read in page memory and only its length is returned.
    """
    target_url = str(getattr(finding, "endpoint_url", "") or "")
    target_origin = _origin(target_url)
    raw = getattr(finding, "raw", {}) or {}
    attack_origin = str(raw.get("origin") or "")
    attack_host = (urlsplit(attack_origin).hostname or "").lower()
    if (not target_origin or _origin(attack_origin) is None
            or urlsplit(attack_origin).scheme.lower() !=
            urlsplit(target_url).scheme.lower()
            or not attack_host.startswith("apex-")
            or not attack_host.endswith(".invalid")
            or attack_origin != str(raw.get("allow_origin") or "")
            or (urlsplit(attack_origin).path not in ("", "/")
                or urlsplit(attack_origin).query
                or urlsplit(attack_origin).fragment)):
        return {"status": "rejected",
                "reason": "candidate lacks a valid matching HTTP origin"}
    try:
        state = _storage_state(identity, target_url)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"status": "unavailable",
                "reason": f"browser credentials unavailable: {exc}"[:300]}

    timeout_ms = max(1000, min(10000, int(timeout_ms)))
    engine = BrowserEngine(
        cfg, headless=getattr(cfg.browser, "headless", True),
        timeout_ms=timeout_ms)
    context = None
    try:
        engine.start()
        context = engine.new_context(
            storage_state=state, identity=str(getattr(identity, "name", "")),
            ignore_https_errors=True, service_workers="block")
        target_requests = [0]
        cookie_sent = [False]
        attack_url = attack_origin.rstrip("/") + "/"
        page_html = (
            "<!doctype html><meta charset=utf-8><title>cors check</title>"
            "<script>window.corsResult = null; window.corsDone = false;"
            f"fetch({json.dumps(target_url)}, {{credentials:'include'}})"
            ".then(async r => { const text = await r.text();"
            "window.corsResult = {status:r.status, ok:r.ok, length:text.length};"
            "window.corsDone = true; })"
            ".catch(() => { window.corsResult = {error:true};"
            "window.corsDone = true; });</script>")

        def guard(route):
            request = route.request
            request_origin = _origin(request.url)
            if (request.url == attack_url and
                    request.resource_type == "document"):
                route.fulfill(status=200, content_type="text/html",
                              body=page_html)
                return
            is_preflight = request.method == "OPTIONS"
            if (request_origin == target_origin and
                    (request.method == "GET" or is_preflight)):
                if is_preflight and (
                        request.headers.get(
                            "access-control-request-method", "").upper()
                        != "GET"):
                    route.abort()
                    return
                target_requests[0] += 1
                if target_requests[0] > _MAX_TARGET_REQUESTS:
                    route.abort()
                    return
                request_headers = request.headers
                cookie_sent[0] = cookie_sent[0] or bool(
                    request_headers.get("cookie"))
                route.continue_()
                return
            route.abort()

        context.route("**/*", guard)
        page = context.new_page()
        browser_errors = []
        page.on("requestfailed", lambda request: browser_errors.append(
            f"{request.method} {urlsplit(request.url).path}: "
            f"{request.failure or 'request failed'}"[:240]))
        page.goto(attack_url, wait_until="domcontentloaded",
                  timeout=timeout_ms)
        page.wait_for_function("window.corsDone === true", timeout=timeout_ms)
        result = page.evaluate("window.corsResult") or {}
        length = int(result.get("length") or 0)
        status_code = int(result.get("status") or 0)
        if result.get("error") or not result.get("ok") or length <= 0:
            return {"status": "not_confirmed",
                    "origin": attack_origin,
                    "cookie_sent": cookie_sent[0],
                    "request_count": target_requests[0],
                    "browser": "chromium",
                    "reason": "browser could not read a non-empty successful response",
                    "browser_error": (browser_errors[-1]
                                      if browser_errors else "")}
        if not cookie_sent[0]:
            return {"status": "not_confirmed",
                    "origin": attack_origin,
                    "response_status": status_code,
                    "response_length": length,
                    "cookie_sent": False,
                    "request_count": target_requests[0],
                    "browser": "chromium",
                    "reason": "data was readable but no configured cookie was sent"}
        return {"status": "confirmed", "origin": attack_origin,
                "response_status": status_code,
                "response_length": length, "cookie_sent": True,
                "request_count": target_requests[0],
                "browser": "chromium",
                "reason": "Chromium read a non-empty response with the configured cookie"}
    except Exception as exc:
        return {"status": "unavailable",
                "reason": f"browser verification failed: {type(exc).__name__}: {exc}"[:300]}
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        engine.stop()
