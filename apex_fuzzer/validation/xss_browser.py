"""Same-origin, read-only Playwright replay for a candidate XSS PoC."""
from urllib.parse import urlsplit
from typing import Dict, Optional
from ..browser.browser import BrowserEngine


def _origin(url: str):
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        return parts.scheme.lower(), parts.hostname.lower(), port
    except ValueError:
        return None


def verify_execution(target_url: str, poc_url: str, marker: str, cfg,
                     headers: Optional[Dict[str, str]] = None) -> Dict:
    """Return executed only when Chromium observes this run's alert marker.

    The PoC must remain same-origin. Browser requests are restricted to at
    most 30 same-origin GETs for the main document and scripts. Other
    resource types, nested documents, state-changing requests, and
    third-party hosts are blocked.
    """
    target_origin = _origin(target_url)
    if not target_origin or _origin(poc_url) != target_origin:
        return {"status": "rejected", "reason": "PoC is not same-origin"}

    bcfg = cfg.browser
    timeout_ms = max(1000, min(
        10000, int(getattr(bcfg, "navigation_timeout_ms", 10000))))
    engine = BrowserEngine(cfg, headless=getattr(bcfg, "headless", True),
                           timeout_ms=timeout_ms)
    context = None
    try:
        engine.start()
        context = engine.new_context()
        safe_headers = {
            name: value for name, value in (headers or {}).items()
            if name.lower() not in {
                "host", "content-length", "connection",
                "transfer-encoding", "origin", "referer",
            }
        }
        if safe_headers:
            context.set_extra_http_headers(safe_headers)

        request_count = [0]

        def guard(route):
            request = route.request
            request_count[0] += 1
            if request.method.upper() != "GET" or request_count[0] > 30:
                route.abort()
                return
            resource_type = getattr(request, "resource_type", "document")
            if resource_type not in {"document", "script"}:
                route.abort()
                return
            frame = getattr(request, "frame", None)
            if (resource_type == "document" and frame is not None and
                    getattr(frame, "parent_frame", None) is not None):
                route.abort()
                return
            if _origin(request.url) == target_origin:
                route.continue_()
            else:
                route.abort()

        context.route("**/*", guard)
        page = context.new_page()
        dialogs = []

        def capture(dialog):
            dialogs.append(dialog.message)
            dialog.accept()

        page.on("dialog", capture)
        try:
            page.goto(poc_url, wait_until="domcontentloaded",
                      timeout=timeout_ms)
        except Exception:
            # A page can reach its PoC and then fail on a blocked redirect or
            # subresource. Dialog capture below remains the proof criterion.
            pass
        page.wait_for_timeout(750)
        executed = marker in dialogs
        return {
            "status": "executed" if executed else "not_executed",
            "dialog_observed": executed,
            "same_origin": True,
            "requests": "same-origin main-document/script GETs (max 30)",
        }
    except Exception as exc:
        return {"status": "unavailable",
                "reason": str(exc)[:300]}
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        engine.stop()
