"""OAuth transition checks: passive authorize-URL analysis plus two
bounded active probes that never redeem codes or follow redirects.

Hunter methodology: OAuth logins fail open when `state` is missing
(CSRF on the login flow), when `response_type=token` puts tokens in
the URL fragment, when PKCE can be stripped, and when `redirect_uri`
points anywhere. The active probes below only *observe* the
authorization endpoint's answer (status + Location header) with a
test identity: no code is ever redeemed, no redirect is ever followed
(the HTTP client refuses redirects), and no foreign host is ever
requested.

Safety contract (bounded, fail-closed):
- passive analysis is offline over already-recorded browser traffic
  and discovered endpoint URLs; zero requests.
- active probes send at most 2 GETs per authorize URL (PKCE strip,
  OAST redirect target) as one configured test identity, in scope
  only, behind the shared budgets; anything but a redirect carrying
  a fresh `code=` to the expected party is inconclusive.
- OAST-redirect probes additionally require a live OAST provider and
  `safety.allow_state_change`, since they initiate login-side state.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("oauth_checks")

_AUTHORIZE_HINTS = ("authorize", "oauth", "/connect", "idp", "sso",
                    "login/callback", "auth/callback")

_RESPONSE_CODE = re.compile(r"(?:^|[?&#])code=([^&#]+)")


@dataclass
class AuthorizeUrl:
    url: str
    has_state: bool = True
    implicit_flow: bool = False
    has_pkce: bool = False
    client_id: str = ""
    redirect_uri: str = ""
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "has_state": self.has_state,
                "implicit_flow": self.implicit_flow,
                "has_pkce": self.has_pkce, "client_id": self.client_id,
                "redirect_uri": self.redirect_uri, "source": self.source}


def _looks_like_authorize(url: str) -> bool:
    try:
        lowered = str(url or "").lower()
    except (TypeError, ValueError):
        return False
    return any(hint in lowered for hint in _AUTHORIZE_HINTS)


def find_authorize_urls(urls, source: str = "") -> List[AuthorizeUrl]:
    """Extract authorization endpoints from recorded/discovered URLs."""
    found: List[AuthorizeUrl] = []
    seen = set()
    for url in urls or []:
        if not isinstance(url, str) or not _looks_like_authorize(url):
            continue
        try:
            query = dict(parse_qsl(urlsplit(url).query,
                                   keep_blank_values=True))
        except (TypeError, ValueError):
            continue
        if "client_id" not in query and "redirect_uri" not in query:
            continue
        key = (urlsplit(url).netloc, query.get("client_id", ""),
               query.get("redirect_uri", ""))
        if key in seen:
            continue
        seen.add(key)
        response_type = query.get("response_type", "")
        found.append(AuthorizeUrl(
            url=url if len(url) <= 500 else "",
            has_state=bool(query.get("state")),
            implicit_flow="token" in response_type.split(),
            has_pkce=bool(query.get("code_challenge")),
            client_id=query.get("client_id", "")[:200],
            redirect_uri=query.get("redirect_uri", "")[:500],
            source=source))
    return [item for item in found if item.url]


@dataclass
class OAuthProbeResult:
    kind: str
    authorize_url: str
    identity: str
    verdict: str = "inconclusive"
    notes: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "authorize_url": self.authorize_url,
                "identity": self.identity, "verdict": self.verdict,
                "notes": self.notes, "evidence": dict(self.evidence)}


def _location_of(response) -> str:
    try:
        headers = getattr(response, "headers", None) or {}
        for name, value in headers.items():
            if str(name).lower() == "location" and isinstance(value, str):
                return value
    except Exception:
        pass
    return ""


def check_pkce_strip(http, authorize_url: str, identity_headers: Dict,
                     identity_name: str, timeout: int = 10
                     ) -> OAuthProbeResult:
    """Replay an authorize URL without PKCE; a fresh code means no bind."""
    res = OAuthProbeResult(kind="pkce-strip", authorize_url=authorize_url,
                           identity=identity_name)
    try:
        parts = urlsplit(authorize_url)
        query = [(k, v) for k, v in
                 parse_qsl(parts.query, keep_blank_values=True)
                 if k not in ("code_challenge", "code_challenge_method",
                              "code_verifier")]
    except (TypeError, ValueError):
        res.notes = "authorize URL is unrepresentable"
        return res
    if "code_challenge" not in dict(parse_qsl(parts.query,
                                              keep_blank_values=True)):
        res.notes = "no PKCE challenge present to strip"
        return res
    stripped = urlunsplit((parts.scheme, parts.netloc, parts.path,
                           urlencode(query, doseq=True), ""))
    try:
        response = http.get(stripped, headers=dict(identity_headers or {}),
                            timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        log.debug("pkce strip probe failed: %s", exc)
        res.notes = "authorize request failed without a response"
        return res
    location = _location_of(response)
    code = _RESPONSE_CODE.search(location)
    if getattr(response, "status_code", 0) in (301, 302, 303, 307, 308) \
            and code:
        res.verdict = "strong_candidate"
        res.notes = ("authorization server issued a code with PKCE "
                     "stripped: challenge is not bound to the flow")
        res.evidence = {"had_code": True,
                        "location_host": urlsplit(location).hostname or ""}
    else:
        res.notes = (f"no code issued without PKCE "
                     f"(HTTP {getattr(response, 'status_code', '?')})")
    return res


def check_redirect_oast(http, authorize_url: str,
                        identity_headers: Dict, identity_name: str,
                        oast_callback_url: str, timeout: int = 10
                        ) -> OAuthProbeResult:
    """Point redirect_uri at our OAST collector and watch the answer.

    Only the 302 Location is read: the client never follows redirects,
    so no request reaches the callback and no code is redeemed. A
    Location aimed at our collector carrying a code proves the
    redirect target is not validated.
    """
    res = OAuthProbeResult(kind="redirect-oast",
                           authorize_url=authorize_url,
                           identity=identity_name)
    if not oast_callback_url:
        res.notes = "no OAST callback available for redirect target"
        return res
    try:
        parts = urlsplit(authorize_url)
        query = [(k, v) for k, v in
                 parse_qsl(parts.query, keep_blank_values=True)
                 if k.lower() != "redirect_uri"]
        query.append(("redirect_uri", oast_callback_url))
    except (TypeError, ValueError):
        res.notes = "authorize URL is unrepresentable"
        return res
    forged = urlunsplit((parts.scheme, parts.netloc, parts.path,
                         urlencode(query, doseq=True), ""))
    try:
        response = http.get(forged, headers=dict(identity_headers or {}),
                            timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        log.debug("redirect-oast probe failed: %s", exc)
        res.notes = "authorize request failed without a response"
        return res
    location = _location_of(response)
    try:
        oast_host = (urlsplit(oast_callback_url).hostname or "").lower()
        loc_host = (urlsplit(location).hostname or "").lower()
    except (TypeError, ValueError):
        res.notes = "redirect location is unrepresentable"
        return res
    if loc_host and loc_host == oast_host and _RESPONSE_CODE.search(
            location):
        res.verdict = "strong_candidate"
        res.notes = ("authorization server redirects with a code to an "
                     "unregistered redirect_uri: open redirector and "
                     "code-disclosure chain")
        res.evidence = {"had_code": True, "location_host": loc_host}
    else:
        res.notes = (f"redirect target not honored "
                     f"(HTTP {getattr(response, 'status_code', '?')})")
    return res
