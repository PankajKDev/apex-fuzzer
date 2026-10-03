"""Playwright browser lifecycle (Phase 1).

Thin wrapper: owns the Playwright driver + Chromium process, hands out
browser contexts. All recording/capture lives in network.py, storage.py
and actions.py; all session modeling in sessions.py. Everything here
degrades gracefully when Playwright is not installed.
"""
from typing import Any, Dict, Optional
from ..logging_setup import get_logger

log = get_logger("browser")


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def chromium_available(timeout_ms: int = 20000) -> bool:
    """True when a real Chromium can actually launch (cached)."""
    global _LAUNCH_CACHE
    if _LAUNCH_CACHE is not None:
        return _LAUNCH_CACHE
    if not playwright_available():
        _LAUNCH_CACHE = False
        return False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto("about:blank", timeout=timeout_ms)
            page.close()
            browser.close()
        _LAUNCH_CACHE = True
    except Exception as e:
        log.debug("chromium launch check failed: %s", e)
        _LAUNCH_CACHE = False
    return _LAUNCH_CACHE


_LAUNCH_CACHE: Optional[bool] = None


class BrowserEngine:
    """Owns playwright + the Chromium process for one scan."""

    def __init__(self, cfg, headless: bool = True,
                 timeout_ms: int = 30000,
                 user_agent: str = "ApexFuzzer/5.2 (+authorized-testing)"):
        self.cfg = cfg
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.user_agent = user_agent
        self._pw = None
        self._browser = None

    @property
    def running(self) -> bool:
        return self._browser is not None

    def start(self):
        if self.running:
            return self
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            raise RuntimeError(
                "playwright not installed — pip install 'apex-fuzzer[browser]'"
            ) from e
        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(
                headless=self.headless)
        except Exception as e:
            self.stop()
            raise RuntimeError(f"chromium launch failed: {e}") from e
        log.info("browser started (headless=%s)", self.headless)
        return self

    def new_context(self, storage_state: Optional[Dict[str, Any]] = None,
                    identity: str = ""):
        if not self.running:
            raise RuntimeError("browser not started — call start() first")
        kw: Dict[str, Any] = {"user_agent": self.user_agent}
        if storage_state:
            kw["storage_state"] = storage_state
        ctx = self._browser.new_context(**kw)
        ctx.set_default_timeout(self.timeout_ms)
        log.debug("browser context opened (identity=%s)", identity or "-")
        return ctx

    def stop(self):
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._pw is not None:
            try:
                self._pw.stop()
            except Exception:
                pass
            self._pw = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
