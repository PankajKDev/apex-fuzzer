"""Safe subprocess execution — argv arrays, timeouts, redaction."""
import subprocess
import re
import threading
import time
from typing import Optional, Sequence
from dataclasses import dataclass
from .logging_setup import get_logger

log = get_logger("shell")


class AdaptiveRateLimiter:
    """Feedback-loop throttler (spec §9).

    Spaces direct HTTP requests at ``base_rate`` req/s. When the target
    starts answering 429/503 the rate halves and an exponential cooldown
    is applied; on healthy responses the rate recovers geometrically up to
    the base rate. This prevents scanner-side 429 cascades and the false
    negatives that timeouts produce.
    """

    MAX_COOLDOWN = 300.0

    def __init__(self, base_rate: float):
        self.base_rate = max(0.1, float(base_rate))
        self.rate = self.base_rate
        self.consecutive_429 = 0
        self.cooldown_until = 0.0
        self._lock = threading.Lock()
        self._next_slot = 0.0

    @property
    def degraded(self) -> bool:
        return self.rate < self.base_rate * 0.9

    def before_request(self):
        with self._lock:
            now = time.time()
            if now < self.cooldown_until:
                sleep_for = self.cooldown_until - now
            else:
                slot = max(now, self._next_slot) + (1.0 / self.rate)
                sleep_for = slot - now
                self._next_slot = slot
        if sleep_for > 0:
            time.sleep(sleep_for)

    def after_response(self, status_code: int):
        with self._lock:
            now = time.time()
            if status_code in (429, 503):
                self.consecutive_429 += 1
                self.rate = max(0.1, self.rate * 0.5)
                self.cooldown_until = now + min(
                    self.MAX_COOLDOWN, 2.0 ** self.consecutive_429)
                log.warning("429/503 from target — backing off "
                            "(rate=%.2f/s, cooldown=%ds)",
                            self.rate, self.consecutive_429)
            elif status_code < 400:
                if self.consecutive_429:
                    self.consecutive_429 -= 1
                self.rate = min(self.base_rate, self.rate * 1.1)
            # 4xx (other than 429) is normal app behavior — leave rate alone

_SECRET_HEADER_RE = re.compile(
    r"(?im)^(authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token)"
    r"\s*:\s*(.+)$"
)
_TOKEN_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|bearer)\b[\"']?"
    r"\s*[:=]\s*"
    r"(['\"]?)([A-Za-z0-9_\-\.]{8,})\2"
)


def redact(text: str) -> str:
    if not text:
        return text

    def _mask_header(m):
        val = m.group(2)
        masked = val[:6] + "*" * max(4, len(val) - 10) + val[-4:] \
            if len(val) > 14 else "***"
        return f"{m.group(1)}: {masked}"

    text = _SECRET_HEADER_RE.sub(_mask_header, text)
    text = _TOKEN_RE.sub(lambda m: f"{m.group(1)}=***", text)
    return text


@dataclass
class CommandResult:
    ok: bool
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


def run(args: Sequence[str], *, timeout: int = 300,
        cwd: Optional[str] = None, env: Optional[dict] = None,
        input_data: Optional[str] = None,
        check: bool = False) -> CommandResult:
    if isinstance(args, str):
        raise TypeError("shell.run requires a list of args, not a string")
    log.debug("exec: %s", " ".join(args))
    try:
        p = subprocess.run(list(args), capture_output=True, text=True,
                           timeout=timeout, cwd=cwd, env=env, input=input_data)
        if check and p.returncode != 0:
            log.warning("command failed rc=%d: %s",
                        p.returncode, " ".join(args))
        return CommandResult(ok=p.returncode == 0, returncode=p.returncode,
                             stdout=p.stdout or "",
                             stderr=redact(p.stderr or ""))
    except subprocess.TimeoutExpired:
        log.warning("command timed out after %ds: %s",
                    timeout, " ".join(args))
        return CommandResult(ok=False, returncode=-1, timed_out=True)
    except FileNotFoundError as e:
        log.error("tool not found: %s", e)
        return CommandResult(ok=False, returncode=-2, stderr=str(e))
    except Exception as e:
        log.error("command error: %s", e)
        return CommandResult(ok=False, returncode=-3, stderr=str(e))


def which(name: str) -> Optional[str]:
    from shutil import which as _w
    return _w(name)


def tool_version(name: str, version_flag: str = "--version",
                 timeout: int = 10) -> Optional[str]:
    if not which(name):
        return None
    r = run([name, version_flag], timeout=timeout)
    if not r.ok:
        return None
    first = (r.stdout or r.stderr).strip().splitlines()
    return first[0] if first else None
