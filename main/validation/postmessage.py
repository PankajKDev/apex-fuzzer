"""postMessage / SOP static checks over cached first-party JS.

Pure offline analysis: no network, no execution. Three patterns:
message handlers without origin validation, wildcard-targetOrigin
postMessage calls (graded by nearby sensitive tokens), and
document.domain relaxation. Every hit is an informational-grade
candidate — static text cannot prove exploitability, so findings
stay medium/low severity with possible confidence and explicit
manual-verification notes.
"""
import re
from typing import Any, Dict, List

from ..logging_setup import get_logger

log = get_logger("postmessage")

_HANDLER_RE = re.compile(
    r"""addEventListener\s*\(\s*["']message["']|\.onmessage\s*=""")
_POSTMESSAGE_RE = re.compile(r"""\.postMessage\s*\(""")
_WILDCARD_ARG_RE = re.compile(r""",\s*["']\*["']""")
_ORIGIN_CHECK_RE = re.compile(
    r"""\.origin\b|origin\s*[=!]==?|trusted[A-Za-z]*[Oo]rigin|"""
    r"""allowed[A-Za-z]*[Oo]rigin|check[A-Za-z]*[Oo]rigin|"""
    r"""valid[A-Za-z]*[Oo]rigin""")
_DOMAIN_RE = re.compile(r"""document\s*\.\s*domain\s*=""")
_SENSITIVE_RE = re.compile(
    r"""token|jwt|auth|session|secret|password|credential|api[_-]?key""",
    re.I)

_HANDLER_WINDOW = 3000
_POST_WINDOW = 500
_CONTEXT_WINDOW = 300
_SNIPPET_LEN = 300


def _line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snippet(text: str, pos: int) -> str:
    start = max(0, pos - 80)
    return " ".join(text[start:pos + _SNIPPET_LEN].split())


def check_message_handlers(js: str) -> List[Dict[str, Any]]:
    """Message listeners whose vicinity shows no origin validation."""
    out = []
    for match in _HANDLER_RE.finditer(js or ""):
        window = js[match.start():match.start() + _HANDLER_WINDOW]
        if _ORIGIN_CHECK_RE.search(window):
            continue
        out.append({"kind": "handler-no-origin-check",
                    "line": _line_no(js, match.start()),
                    "snippet": _snippet(js, match.start())})
    return out


def check_wildcard_posts(js: str) -> List[Dict[str, Any]]:
    """postMessage calls with a "*" targetOrigin."""
    out = []
    for match in _POSTMESSAGE_RE.finditer(js or ""):
        args = js[match.start():match.start() + _POST_WINDOW]
        if not _WILDCARD_ARG_RE.search(args):
            continue
        context = js[max(0, match.start() - _CONTEXT_WINDOW):
                     match.start() + _POST_WINDOW]
        sensitive = bool(_SENSITIVE_RE.search(context))
        out.append({"kind": "wildcard-target-origin",
                    "line": _line_no(js, match.start()),
                    "sensitive": sensitive,
                    "snippet": _snippet(js, match.start())})
    return out


def check_document_domain(js: str) -> List[Dict[str, Any]]:
    """document.domain assignments relax same-origin checks."""
    return [{"kind": "document-domain",
             "line": _line_no(js, match.start()),
             "snippet": _snippet(js, match.start())}
            for match in _DOMAIN_RE.finditer(js or "")]


def check_javascript(js: str) -> List[Dict[str, Any]]:
    """All three checks over one bundle, handler order preserved."""
    return (check_message_handlers(js) + check_wildcard_posts(js)
            + check_document_domain(js))
