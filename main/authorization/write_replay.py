"""BOLA write replay: the MTN-pattern check real hackers run.

Methodology (from disclosed writeups):
1. Two accounts: harvest the victim's object ID from one endpoint's
   response (as the owner).
2. Take the *attacker's own* mutating request shape (their values),
   swap in the *victim's* ID, send as the attacker.
3. Verify: re-read the victim object and check the attacker's values
   persisted there.

Safety contract (bounded, fail-closed):
- opt-in only (`authorization.write_replay`) plus
  `safety.allow_state_change`; off by default, no invented writes.
- replay requires an observed attacker POST/PUT/PATCH shape containing
  the identifier; without one the attempt is inconclusive (never
  synthesize a mutating body from metadata).
- ambiguous shapes (>1 distinct attacker shape for endpoint+param)
  fail closed without sending.
- text shapes only (form-urlencoded, JSON incl. nested, XML leaf,
  query on mutating methods); multipart/binary/oversized fail closed.
- at most 3 requests per (endpoint, param, victim): owner baseline
  GET, one replay, one readback GET.
- verdicts: accepted-but-unverified stays a candidate; only a clean
  readback showing the attacker's values newly persisted confirms;
  a 200 readback identical to the pre-replay baseline refutes to
  inconclusive. Marker *values* stay runtime-only; evidence keeps
  field names and booleans.

BFLA method proof (same file, same gates): for a BFLA candidate cell
the lower-privilege identity's own observed mutating shape is replayed
as that identity — no ID swap, since the question is whether the
*function* executes, not which object it touches — and a privileged
reader checks persistence via readback. Accepted-but-unverified keeps
the sweep candidate standing (the sweep 200s already show identical
treatment); only newly-persisted markers confirm. A denied replay
conflicts with the sweep's 200, so per the conflict rule it stays
inconclusive instead of becoming a negative.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, urlencode

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("write_replay")

REPLAY_METHODS = ("POST", "PUT", "PATCH")
_READ_METHOD = "GET"

_HOP_HEADERS = {"host", "content-length", "connection",
                "transfer-encoding"}

# values under these keys never become persistence markers
_SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "csrf",
                   "xsrf", "session", "sessionid", "nonce", "timestamp",
                   "date", "otp", "captcha", "signature", "auth",
                   "authorization", "cookie", "set-cookie"}

_MIN_MARKER_LEN = 3


@dataclass
class WriteReplayResult:
    endpoint_url: str
    method: str
    param: str
    victim_value: str
    owner: str
    tester: str
    owner_tenant: str = ""
    tester_tenant: str = ""
    status: int = 0
    replay_accepted: bool = False
    edge_denied: bool = False
    readback: str = "unverified"
    verdict: str = "inconclusive"
    notes: str = ""
    markers_matched: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint_url": self.endpoint_url, "method": self.method,
                "param": self.param, "victim_value": self.victim_value,
                "owner": self.owner, "tester": self.tester,
                "owner_tenant": self.owner_tenant,
                "tester_tenant": self.tester_tenant,
                "status": self.status,
                "replay_accepted": self.replay_accepted,
                "readback": self.readback, "verdict": self.verdict,
                "notes": self.notes,
                "edge_denied": self.edge_denied,
                "markers_matched": list(self.markers_matched)}


def _read_url(replay_url: str, param: str, victim: str) -> Optional[str]:
    """Same-path GET read URL carrying the victim identifier.

    Preserves the replay URL's other query parameters (routing/paging
    context) and only swaps the identifier itself.
    """
    from urllib.parse import parse_qsl
    try:
        parts = urlsplit(replay_url)
    except (TypeError, ValueError):
        return None
    if parts.scheme.lower() not in ("http", "https") or \
            not parts.hostname:
        return None
    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
    except (TypeError, ValueError):
        pairs = []
    if any(key == param for key, _ in pairs):
        query = [(key, victim if key == param else value)
                 for key, value in pairs]
    else:
        query = pairs + [(param, victim)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query, doseq=True), ""))


def _shape_markers(shape: Dict[str, Any], param: str) -> Dict[str, str]:
    """Attacker scalar values usable as persistence markers.

    Everything except the swapped identifier itself, identifier-like
    keys, and sensitive/volatile keys. Values stay runtime-only.
    """
    from ..application.resources import IDENTIFIER_NAMES
    from urllib.parse import parse_qsl, urlsplit
    markers: Dict[str, str] = {}

    def consider(key: Any, value: Any) -> None:
        name = str(key or "")
        text = "" if value is None else str(value)
        if not name or len(text) < _MIN_MARKER_LEN:
            return
        lowered = name.lower()
        if lowered in IDENTIFIER_NAMES or lowered in _SENSITIVE_KEYS:
            return
        if name == param:
            return
        markers.setdefault(name, text)

    try:
        for key, value in parse_qsl(
                urlsplit(str(shape.get("url") or "")).query,
                keep_blank_values=True):
            if key != param:
                consider(key, value)
    except (TypeError, ValueError):
        pass
    body = shape.get("post_data")
    if isinstance(body, (bytes, bytearray)):
        try:
            body = bytes(body).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return markers
    if not isinstance(body, str) or not body.strip():
        return markers
    content_type = str(shape.get("content_type") or "")
    for name, value in _flat_body_values(body, content_type).items():
        consider(name, value)
    return markers


def _nested_value(data: Any, parameter: str) -> Any:
    """Read back a dotted/indexed JSON path (structural, encoding-safe)."""
    import re
    parts = re.findall(r"[^.\[\]]+|\[\d*\]", parameter or "")
    current: Any = data
    for raw in parts:
        if raw.startswith("["):
            if not isinstance(current, list):
                return None
            slot = raw[1:-1]
            pos = int(slot) if slot.isdigit() else 0
            if pos >= len(current):
                return None
            current = current[pos]
        else:
            if not isinstance(current, dict) or raw not in current:
                return None
            current = current[raw]
    return current


def _flat_body_values(body: str, content_type: str) -> Dict[str, str]:
    """Scalar body values keyed by field name (dotted for nested JSON)."""
    import json as _json
    from urllib.parse import parse_qsl
    ctype = (content_type or "").lower()
    if "json" in ctype:
        try:
            data = _json.loads(body)
        except (ValueError, TypeError):
            return {}
        flat: Dict[str, str] = {}

        def walk(node: Any, prefix: str, depth: int = 0) -> None:
            if depth > 6:
                return
            if isinstance(node, dict):
                for key, item in node.items():
                    name = f"{prefix}.{key}" if prefix else str(key)
                    if isinstance(item, (dict, list)):
                        walk(item, name, depth + 1)
                    elif isinstance(item, (str, int, float)) and \
                            not isinstance(item, bool):
                        flat[name] = str(item)
            elif isinstance(node, list):
                for item in node[:20]:
                    walk(item, prefix, depth + 1)

        walk(data, "")
        return flat
    if "xml" in ctype:
        import xml.etree.ElementTree as _et
        try:
            root = _et.fromstring(body)
        except (_et.ParseError, ValueError):
            return {}
        return {el.tag: (el.text or "") for el in root.iter()
                if not list(el) and (el.text or "").strip()}
    return dict(parse_qsl(body, keep_blank_values=True))


def _attacker_shapes(endpoint: Any, param: str, tester: str,
                     scope=None) -> Tuple[List[Dict[str, Any]], str]:
    """Retained attacker mutating shapes for endpoint+param.

    Returns (shapes, reason). Ambiguous or unusable input yields ([], reason).
    """
    from ..validation.observed_sqli import (
        _body_has_parameter, _content_type_of, _endpoint_key, _parse_url,
        _post_data_text, _query_has_parameter, _supported_body_content_type,
        _valid_identity, SUPPORTED_METHODS)
    observed = list(getattr(endpoint, "observed_requests", []) or [])
    target_key = _endpoint_key(getattr(endpoint, "url", "") or "")
    if target_key is None:
        return [], "candidate endpoint URL is unrepresentable"
    shapes = []
    skipped_scope = 0
    for entry in observed:
        if not isinstance(entry, dict):
            continue
        method = str(entry.get("method") or "GET").upper()
        if method not in REPLAY_METHODS or method not in SUPPORTED_METHODS:
            continue
        if _valid_identity(entry.get("identity", "anonymous")) != tester:
            continue
        url = entry.get("url")
        if not isinstance(url, str) or _parse_url(url) is None:
            continue
        if _endpoint_key(url) != target_key:
            continue
        if scope is not None:
            try:
                if not scope.active_test_allowed(url):
                    skipped_scope += 1
                    continue
            except Exception:
                skipped_scope += 1
                continue
        ctype = _content_type_of(entry)
        if "multipart/" in (ctype or "").lower():
            continue
        if _query_has_parameter(url, param):
            body_text, problem = _post_data_text(entry.get("post_data"))
            if problem or body_text:
                continue
            shapes.append(entry)
            continue
        if not _supported_body_content_type(ctype):
            continue
        body_text, problem = _post_data_text(entry.get("post_data"))
        if problem:
            continue
        if _body_has_parameter(ctype, body_text, param):
            shapes.append(entry)
    if not shapes:
        if skipped_scope:
            return [], ("no in-scope observed mutating request carries "
                         f"{param!r} for {tester!r}")
        return [], f"no observed {tester} mutating request carries {param!r}"
    distinct = {(str(s.get("method")), str(s.get("url")),
                 _content_type_of(s), repr(s.get("post_data")))
                for s in shapes}
    if len(distinct) > 1:
        return [], ("ambiguous observed requests for "
                     f"{param!r}; fail closed without guessing")
    return [shapes[0]], "matched one observed mutating request"


def _build_replay(shape: Dict[str, Any], param: str, victim: str,
                  tester_headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Render one replay request with the victim ID swapped in.

    Returns None when the shape cannot be rebuilt faithfully.
    """
    from ..validation.observed_sqli import (
        _content_type_of, _query_has_parameter)
    from urllib.parse import parse_qsl, urlsplit, urlunsplit
    method = str(shape.get("method") or "POST").upper()
    url = str(shape.get("url") or "")
    headers: Dict[str, str] = {}
    raw_headers = shape.get("headers") or {}
    if isinstance(raw_headers, dict):
        for name, value in raw_headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                return None
            if not name.strip() or name.strip().lower() in _HOP_HEADERS:
                continue
            headers[name.strip()] = value.strip()
    for name, value in (tester_headers or {}).items():
        if isinstance(name, str) and isinstance(value, str) and name.strip():
            headers[name.strip()] = value.strip()
    ctype = _content_type_of(shape)
    if _query_has_parameter(url, param):
        parts = urlsplit(url)
        query = [(k, victim if k == param else v) for k, v in parse_qsl(
            parts.query, keep_blank_values=True)]
        target = urlunsplit((parts.scheme, parts.netloc, parts.path,
                             urlencode(query, doseq=True), ""))
        return {"method": method, "url": target, "headers": headers,
                "kind": "query"}
    body = shape.get("post_data")
    if isinstance(body, (bytes, bytearray)):
        try:
            body = bytes(body).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return None
    if not isinstance(body, str):
        return None
    lowered = (ctype or "").lower()
    if "json" in lowered:
        import json as _json
        try:
            data = _json.loads(body)
        except (ValueError, TypeError):
            return None
        from ..validation.request_shape import _assign_nested
        _assign_nested(data, param, victim)
        if _nested_value(data, param) != victim:
            return None
        return {"method": method, "url": url, "headers": headers,
                "kind": "json",
                "body": _json.dumps(data, separators=(",", ":"),
                                    ensure_ascii=False)}
    if "xml" in lowered:
        from ..validation.request_shape import xml_body_with_parameter
        from types import SimpleNamespace
        probe = SimpleNamespace(request_body=body,
                                request_content_type=ctype)
        try:
            rebuilt = xml_body_with_parameter(probe, param, victim)
        except ValueError:
            return None
        return {"method": method, "url": url, "headers": headers,
                "kind": "xml", "body": rebuilt}
    if (ctype or "").split(";", 1)[0].strip().lower() != \
            "application/x-www-form-urlencoded":
        return None
    pairs = [(k, victim if k == param else v) for k, v in parse_qsl(
        body, keep_blank_values=True)]
    if not any(k == param for k, _ in pairs):
        return None
    return {"method": method, "url": url, "headers": headers,
            "kind": "form", "body": urlencode(pairs, doseq=True)}


def replay_writes(http, endpoint: Any, victims: List[Any], tester: Any,
                  owner_headers: Dict[str, Dict[str, str]],
                  timeout: int = 10, max_ids: int = 3,
                  scope=None) -> List[WriteReplayResult]:
    """Replay attacker shapes with victim IDs; verify via readback."""
    from ..validation.differential import normalize_response
    out: List[WriteReplayResult] = []
    tester_name = getattr(tester, "name", "anonymous")
    tester_tenant = getattr(tester, "tenant", "") or ""
    tester_headers = dict(getattr(tester, "auth_headers", None) or {})
    tried = 0
    seen_victims = set()
    for victim in victims or []:
        if tried >= max_ids:
            break
        owner = getattr(victim, "owner", "")
        if not owner or owner == tester_name:
            continue
        param = getattr(victim, "param", "")
        value = getattr(victim, "value", "")
        if not param or not value:
            continue
        key = (param, value, owner)
        if key in seen_victims:
            continue
        seen_victims.add(key)
        owner_tenant = getattr(victim, "owner_tenant", "") or ""
        tried += 1
        shapes, reason = _attacker_shapes(endpoint, param, tester_name,
                                         scope=scope)
        if not shapes:
            out.append(WriteReplayResult(
                endpoint_url=getattr(endpoint, "url", ""),
                method="", param=param, victim_value=value,
                owner=owner, tester=tester_name,
                owner_tenant=owner_tenant, tester_tenant=tester_tenant,
                notes=f"write replay skipped: {reason}"))
            continue
        shape = shapes[0]
        try:
            replay = _build_replay(shape, param, value, tester_headers)
        except (ValueError, TypeError) as exc:
            out.append(WriteReplayResult(
                endpoint_url=getattr(endpoint, "url", ""),
                method=str(shape.get("method") or ""), param=param,
                victim_value=value, owner=owner, tester=tester_name,
                owner_tenant=owner_tenant, tester_tenant=tester_tenant,
                notes=f"write replay skipped: cannot rebuild shape ({exc})"))
            continue
        if replay is None:
            out.append(WriteReplayResult(
                endpoint_url=getattr(endpoint, "url", ""),
                method=str(shape.get("method") or ""), param=param,
                victim_value=value, owner=owner, tester=tester_name,
                owner_tenant=owner_tenant, tester_tenant=tester_tenant,
                notes="write replay skipped: shape cannot be rebuilt "
                      "faithfully"))
            continue
        read_url = _read_url(replay["url"], param, value)
        if read_url is None or (
                scope is not None and not scope.active_test_allowed(
                    replay["url"])):
            out.append(WriteReplayResult(
                endpoint_url=replay["url"], method=replay["method"],
                param=param, victim_value=value, owner=owner,
                tester=tester_name, owner_tenant=owner_tenant,
                tester_tenant=tester_tenant,
                notes="write replay skipped: replay URL out of scope "
                      "or unrepresentable"))
            continue
        markers = _shape_markers(shape, param)
        # owner baseline BEFORE the replay (readback comparison needs it)
        baseline_text: Optional[str] = None
        baseline_norm = None
        try:
            base = http.get(
                read_url,
                headers=dict((owner_headers or {}).get(owner) or {}),
                timeout=timeout)
            if base.status_code == 200:
                baseline_text = base.text or ""
                baseline_norm = normalize_response(base)
        except BudgetExceeded:
            raise
        except Exception as exc:
            log.debug("write-replay baseline %s failed: %s", read_url, exc)
        # the replay itself: attacker's values, victim's ID, as attacker.
        # The HTTP client enforces scope-adjacent budgets itself.
        try:
            kwargs: Dict[str, Any] = {"headers": replay["headers"],
                                      "timeout": timeout}
            if replay.get("body") is not None:
                kwargs["data"] = replay["body"]
            response = http.request(replay["method"], replay["url"],
                                    **kwargs)
        except BudgetExceeded:
            raise
        except Exception as exc:
            log.debug("write replay %s %s failed: %s",
                      replay["method"], replay["url"], exc)
            out.append(WriteReplayResult(
                endpoint_url=replay["url"], method=replay["method"],
                param=param, victim_value=value, owner=owner,
                tester=tester_name, owner_tenant=owner_tenant,
                tester_tenant=tester_tenant,
                notes="write replay request failed without a response"))
            continue
        accepted = 200 <= response.status_code < 300 and (
            value in (response.text or ""))
        from ..validation.differential import looks_like_edge_deny
        try:
            replay_edge = looks_like_edge_deny(
                response.status_code, response.text or "",
                getattr(response, "headers", None))
        except Exception:
            replay_edge = False
        res = WriteReplayResult(
            endpoint_url=replay["url"], method=replay["method"],
            param=param, victim_value=value, owner=owner,
            tester=tester_name, owner_tenant=owner_tenant,
            tester_tenant=tester_tenant, status=response.status_code,
            replay_accepted=bool(accepted),
            edge_denied=bool(replay_edge))
        if not accepted:
            res.notes = (f"replay not accepted ({tester_name}→"
                         f"{response.status_code}); no write proven")
            out.append(res)
            continue
        # readback as the owner: do the attacker's values now live on
        # the victim object?
        try:
            check = http.get(
                read_url,
                headers=dict((owner_headers or {}).get(owner) or {}),
                timeout=timeout)
        except BudgetExceeded:
            raise
        except Exception as exc:
            log.debug("write-replay readback %s failed: %s", read_url, exc)
            res.verdict = "strong_candidate"
            res.notes = (f"BOLA write: '{tester_name}' replay accepted "
                         f"({response.status_code}) for '{owner}''s "
                         f"'{param}={value}'; readback unavailable so the "
                         f"candidate stands unverified")
            out.append(res)
            continue
        if check.status_code != 200:
            res.verdict = "strong_candidate"
            res.notes = (f"BOLA write: '{tester_name}' replay accepted "
                         f"({response.status_code}) for '{owner}''s "
                         f"'{param}={value}'; readback "
                         f"{check.status_code} so the candidate stands")
            out.append(res)
            continue
        text = check.text or ""
        newly = [name for name, marker in markers.items()
                 if marker in text and (
                     baseline_text is None or marker not in baseline_text)]
        if baseline_text is not None and newly:
            res.verdict = "confirmed"
            res.readback = "confirmed-persisted"
            res.markers_matched = sorted(newly)
            res.notes = (f"BOLA write confirmed: '{tester_name}''s values "
                         f"({', '.join(sorted(newly))}) now persist on "
                         f"'{owner}''s '{param}={value}'")
            out.append(res)
            continue
        if baseline_norm is not None:
            try:
                current = normalize_response(check)
            except Exception:
                current = None
            if current is not None and current.get("key_shape") == \
                    baseline_norm.get("key_shape") and \
                    current.get("body_hash") == \
                    baseline_norm.get("body_hash"):
                res.verdict = "inconclusive"
                res.readback = "refuted-clean"
                res.notes = ("replay accepted but a clean re-read matches "
                             "the pre-replay baseline: no persistence "
                             "observed")
                out.append(res)
                continue
        res.verdict = "strong_candidate"
        res.readback = "unverified"
        res.notes = (f"BOLA write: '{tester_name}' replay accepted "
                     f"({response.status_code}) for '{owner}''s "
                     f"'{param}={value}'; readback could not prove "
                     f"persistence so the candidate stands")
        out.append(res)
    return out


# BFLA methods eligible for state-changing proof. DELETE has no body
# semantics in the retained-shape helpers, so it stays sweep-only.
PROOF_METHODS = ("POST", "PUT", "PATCH")


@dataclass
class BflaProofResult:
    endpoint_url: str
    method: str
    tester: str
    reader: str
    status: int = 0
    replay_accepted: bool = False
    edge_denied: bool = False
    readback: str = "unverified"
    verdict: str = "inconclusive"
    notes: str = ""
    markers_matched: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint_url": self.endpoint_url, "method": self.method,
                "tester": self.tester, "reader": self.reader,
                "status": self.status,
                "replay_accepted": self.replay_accepted,
                "readback": self.readback, "verdict": self.verdict,
                "notes": self.notes,
                "edge_denied": self.edge_denied,
                "markers_matched": list(self.markers_matched)}


def _tester_method_shapes(endpoint: Any, method: str, tester: str,
                          scope=None) -> Tuple[List[Dict[str, Any]], str]:
    """Retained tester shapes for one (endpoint, method) cell.

    Unlike the victim-ID replay above, no parameter is required: the
    tester's own shape is replayed verbatim. The shape must still
    carry attacker-controlled values (a query string or a supported
    non-empty body) — replaying an empty shape would just repeat the
    sweep request and prove nothing new. Returns (shapes, reason).
    """
    from ..validation.observed_sqli import (
        _content_type_of, _endpoint_key, _parse_url, _post_data_text,
        _supported_body_content_type, _valid_identity)
    from urllib.parse import urlsplit
    observed = list(getattr(endpoint, "observed_requests", []) or [])
    target_key = _endpoint_key(getattr(endpoint, "url", "") or "")
    if target_key is None:
        return [], "candidate endpoint URL is unrepresentable"
    shapes = []
    skipped_scope = 0
    for entry in observed:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("method") or "GET").upper() != method:
            continue
        if _valid_identity(entry.get("identity", "anonymous")) != tester:
            continue
        url = entry.get("url")
        if not isinstance(url, str) or _parse_url(url) is None:
            continue
        if _endpoint_key(url) != target_key:
            continue
        if scope is not None:
            try:
                if not scope.active_test_allowed(url):
                    skipped_scope += 1
                    continue
            except Exception:
                skipped_scope += 1
                continue
        ctype = _content_type_of(entry)
        if "multipart/" in (ctype or "").lower():
            continue
        body_text, problem = _post_data_text(entry.get("post_data"))
        if problem:
            continue
        if body_text:
            if not _supported_body_content_type(ctype):
                continue
        else:
            try:
                if not urlsplit(url).query.strip():
                    continue
            except (TypeError, ValueError):
                continue
        shapes.append(entry)
    if not shapes:
        if skipped_scope:
            return [], ("no in-scope observed mutating request with "
                        f"values for {tester!r} {method}")
        return [], f"no observed {tester} {method} shape carries values"
    distinct = {(str(s.get("method")), str(s.get("url")),
                 _content_type_of(s), repr(s.get("post_data")))
                for s in shapes}
    if len(distinct) > 1:
        return [], ("ambiguous observed requests for "
                    f"{tester!r} {method}; fail closed without guessing")
    return [shapes[0]], "matched one observed mutating request"


def _build_direct(shape: Dict[str, Any],
                  auth_headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Render a verbatim replay of the tester's own shape (no ID swap)."""
    method = str(shape.get("method") or "POST").upper()
    url = str(shape.get("url") or "")
    headers: Dict[str, str] = {}
    raw_headers = shape.get("headers") or {}
    if isinstance(raw_headers, dict):
        for name, value in raw_headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                return None
            if not name.strip() or name.strip().lower() in _HOP_HEADERS:
                continue
            headers[name.strip()] = value.strip()
    for name, value in (auth_headers or {}).items():
        if isinstance(name, str) and isinstance(value, str) and name.strip():
            headers[name.strip()] = value.strip()
    body = shape.get("post_data")
    if isinstance(body, (bytes, bytearray)):
        try:
            body = bytes(body).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return None
    if body is None:
        body = ""
    if not isinstance(body, str):
        return None
    return {"method": method, "url": url, "headers": headers,
            "body": body}


def _bfla_read_url(endpoint: Any, reader: str) -> Optional[str]:
    """State-revealing GET URL: the reader's observed shape, else the
    endpoint URL itself. The caller scope-checks the result."""
    from ..validation.observed_sqli import (
        _endpoint_key, _parse_url, _valid_identity)
    target_key = _endpoint_key(getattr(endpoint, "url", "") or "")
    if target_key is None:
        return None
    for entry in list(getattr(endpoint, "observed_requests", []) or []):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("method") or "").upper() != _READ_METHOD:
            continue
        if _valid_identity(entry.get("identity", "anonymous")) != reader:
            continue
        url = entry.get("url")
        if isinstance(url, str) and _parse_url(url) is not None \
                and _endpoint_key(url) == target_key:
            return url
    url = getattr(endpoint, "url", "") or ""
    if not isinstance(url, str) or _parse_url(url) is None:
        return None
    return url


def prove_bfla(http, endpoint: Any, method: str, tester: Any,
               reader: Any, owner_headers: Dict[str, Dict[str, str]],
               timeout: int = 10, scope=None) -> BflaProofResult:
    """Replay the tester's observed shape; a privileged reader readback
    decides. At most 3 requests: baseline GET, one replay, one readback.
    Only newly-persisted markers confirm; every other outcome leaves
    the sweep candidate standing (verdict "strong_candidate" for an
    accepted-but-unproven replay, "inconclusive" otherwise)."""
    tester_name = getattr(tester, "name", "anonymous") or "anonymous"
    reader_name = getattr(reader, "name", "anonymous") or "anonymous"
    base = {"endpoint_url": getattr(endpoint, "url", ""),
            "method": method, "tester": tester_name,
            "reader": reader_name}

    def done(**kw: Any) -> BflaProofResult:
        args = dict(base)
        args.update(kw)
        return BflaProofResult(**args)

    if method not in PROOF_METHODS:
        return done(notes=(
            f"BFLA proof skipped: {method} has no replayable body "
            "semantics; the sweep candidate stands"))
    shapes, reason = _tester_method_shapes(endpoint, method, tester_name,
                                          scope=scope)
    if not shapes:
        return done(notes=f"BFLA proof skipped: {reason}")
    shape = shapes[0]
    tester_headers = dict((owner_headers or {}).get(tester_name) or
                          getattr(tester, "auth_headers", None) or {})
    reader_headers = dict((owner_headers or {}).get(reader_name) or
                          getattr(reader, "auth_headers", None) or {})
    replay = _build_direct(shape, tester_headers)
    if replay is None:
        return done(notes="BFLA proof skipped: shape cannot be "
                          "rebuilt faithfully")
    read_url = _bfla_read_url(endpoint, reader_name)
    read_ok = read_url is not None
    if read_ok and scope is not None:
        try:
            read_ok = bool(scope.active_test_allowed(read_url))
        except Exception:
            read_ok = False
    if not read_ok:
        return done(notes="BFLA proof skipped: read URL out of scope "
                          "or unrepresentable")
    markers = _shape_markers(shape, "")
    # reader baseline BEFORE the replay (persistence needs the delta)
    baseline_text: Optional[str] = None
    try:
        base_resp = http.get(read_url, headers=reader_headers,
                             timeout=timeout)
        if base_resp.status_code == 200:
            baseline_text = base_resp.text or ""
    except BudgetExceeded:
        raise
    except Exception as exc:
        log.debug("bfla-proof baseline %s failed: %s", read_url, exc)
    try:
        kwargs: Dict[str, Any] = {"headers": replay["headers"],
                                  "timeout": timeout}
        if replay.get("body"):
            kwargs["data"] = replay["body"]
        response = http.request(replay["method"], replay["url"],
                                **kwargs)
    except BudgetExceeded:
        raise
    except Exception as exc:
        log.debug("bfla-proof replay %s %s failed: %s",
                  replay["method"], replay["url"], exc)
        return done(notes="BFLA proof request failed without a response")
    accepted = 200 <= response.status_code < 300
    from ..validation.differential import looks_like_edge_deny
    try:
        replay_edge = looks_like_edge_deny(
            response.status_code, response.text or "",
            getattr(response, "headers", None))
    except Exception:
        replay_edge = False
    if replay_edge:
        return done(status=response.status_code, edge_denied=True,
                    notes="BFLA proof hit edge/bot-wall infrastructure, "
                          "not the app; the sweep candidate stands")
    if not accepted:
        return done(
            status=response.status_code,
            notes=(f"BFLA proof replay denied ({tester_name}→"
                   f"{response.status_code}); the sweep already saw a "
                   "200 for this identity and method, so the denial "
                   "reads as input validation and the candidate stands"))
    try:
        check = http.get(read_url, headers=reader_headers,
                         timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        log.debug("bfla-proof readback %s failed: %s", read_url, exc)
        return done(status=response.status_code, replay_accepted=True,
                    notes=(f"BFLA {method} as '{tester_name}' accepted "
                           f"({response.status_code}); readback "
                           "unavailable so the candidate stands "
                           "unverified"))
    if check.status_code != 200:
        return done(
            status=response.status_code, replay_accepted=True,
            notes=(f"BFLA {method} as '{tester_name}' accepted "
                   f"({response.status_code}); readback "
                   f"{check.status_code} so the candidate stands"))
    text = check.text or ""
    newly = [name for name, marker in markers.items()
             if marker in text and (
                 baseline_text is None or marker not in baseline_text)]
    if baseline_text is not None and newly:
        return done(
            status=response.status_code, replay_accepted=True,
            readback="confirmed-persisted", verdict="confirmed",
            markers_matched=sorted(newly),
            notes=(f"BFLA confirmed: '{tester_name}''s {method} values "
                   f"({', '.join(sorted(newly))}) now persist "
                   f"(read as '{reader_name}')"))
    return done(
        status=response.status_code, replay_accepted=True,
        readback="no-persistence-observed", verdict="strong_candidate",
        notes=(f"BFLA {method} as '{tester_name}' accepted "
               f"({response.status_code}) but the readback shows no "
               "newly-persisted values, so the sweep candidate stands "
               "unproven"))


# Privileged-looking fields for the self-object mass-assignment check.
# The probe value is never a real role: persistence proves the binder
# accepted the field, nothing more.
MASS_FIELDS = ("role", "is_admin")
MASS_PROBE_VALUE = "apex-mass-probe"


@dataclass
class MassAssignmentResult:
    endpoint_url: str
    method: str
    field: str
    tester: str
    status: int = 0
    replay_accepted: bool = False
    edge_denied: bool = False
    readback: str = "unverified"
    verdict: str = "inconclusive"
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint_url": self.endpoint_url, "method": self.method,
                "field": self.field, "tester": self.tester,
                "status": self.status,
                "replay_accepted": self.replay_accepted,
                "readback": self.readback, "verdict": self.verdict,
                "notes": self.notes,
                "edge_denied": self.edge_denied}


def _build_with_extra(shape: Dict[str, Any],
                      auth_headers: Dict[str, str],
                      field_name: str, value: str
                      ) -> Optional[Dict[str, Any]]:
    """Verbatim replay plus one injected top-level field.

    Returns None when the shape already binds the field (nothing to
    prove), the body kind is unsupported, or the shape cannot be
    rebuilt faithfully.
    """
    from urllib.parse import parse_qsl, urlsplit, urlunsplit
    replay = _build_direct(shape, auth_headers)
    if replay is None:
        return None
    try:
        has_query = bool(urlsplit(replay["url"]).query.strip())
    except (TypeError, ValueError):
        return None
    if has_query and not (replay.get("body") or ""):
        parts = urlsplit(replay["url"])
        try:
            query = parse_qsl(parts.query, keep_blank_values=True)
        except (TypeError, ValueError):
            return None
        if any(key == field_name for key, _ in query):
            return None
        query.append((field_name, value))
        replay["url"] = urlunsplit(
            (parts.scheme, parts.netloc, parts.path,
             urlencode(query, doseq=True), ""))
        replay["kind"] = "query"
        return replay
    body = replay.get("body") or ""
    ctype = ""
    for name, header_value in (replay.get("headers") or {}).items():
        if str(name).lower() == "content-type":
            ctype = str(header_value)
            break
    lowered = (ctype or "").lower()
    if "json" in lowered:
        import json as _json
        try:
            data = _json.loads(body)
        except (ValueError, TypeError):
            return None
        if not isinstance(data, dict) or field_name in data:
            return None
        data[field_name] = value
        replay["body"] = _json.dumps(data, separators=(",", ":"),
                                     ensure_ascii=False)
        replay["kind"] = "json"
        return replay
    if (ctype or "").split(";", 1)[0].strip().lower() == \
            "application/x-www-form-urlencoded":
        try:
            pairs = parse_qsl(body, keep_blank_values=True)
        except (TypeError, ValueError):
            return None
        if any(key == field_name for key, _ in pairs):
            return None
        pairs.append((field_name, value))
        replay["body"] = urlencode(pairs, doseq=True)
        replay["kind"] = "form"
        return replay
    return None


def replay_mass_assignment(http, endpoint: Any, tester: Any,
                           owner_headers: Dict[str, Dict[str, str]],
                           fields: tuple = MASS_FIELDS,
                           timeout: int = 10, scope=None
                           ) -> List[MassAssignmentResult]:
    """Inject privileged-looking fields into the tester's OWN object.

    The tester's observed mutating shape replays with one added field;
    the tester's own object is read back before and after. A newly
    persisted probe value is a mass-assignment candidate (the binder
    accepted the field; impact still needs human judgment, so this
    never confirms). A completed 4xx denial against a 200 own-object
    baseline is a genuine negative.
    """
    tester_name = getattr(tester, "name", "anonymous") or "anonymous"
    base = {"endpoint_url": getattr(endpoint, "url", ""),
            "tester": tester_name}

    def done(method: str = "", field_name: str = "",
             **kw: Any) -> MassAssignmentResult:
        args = dict(base, method=method, field=field_name)
        args.update(kw)
        return MassAssignmentResult(**args)

    shape = None
    method = ""
    reason = "no observed mutating shape with values"
    for candidate_method in PROOF_METHODS:
        found, why = _tester_method_shapes(
            endpoint, candidate_method, tester_name, scope=scope)
        if found:
            shape, method = found[0], candidate_method
            break
        reason = why
    if shape is None:
        return [done(notes=f"mass assignment skipped: {reason}")]
    tester_headers = dict((owner_headers or {}).get(tester_name) or
                          getattr(tester, "auth_headers", None) or {})
    read_url = _bfla_read_url(endpoint, tester_name)
    read_ok = read_url is not None
    if read_ok and scope is not None:
        try:
            read_ok = bool(scope.active_test_allowed(read_url))
        except Exception:
            read_ok = False
    if not read_ok:
        return [done(method=method,
                     notes="mass assignment skipped: read URL out of "
                           "scope or unrepresentable")]
    try:
        base_resp = http.get(read_url, headers=tester_headers,
                             timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        log.debug("mass-assignment baseline %s failed: %s",
                  read_url, exc)
        return [done(method=method,
                     notes="mass assignment skipped: own-object "
                           "baseline unavailable")]
    if base_resp.status_code != 200:
        return [done(method=method,
                     notes="mass assignment skipped: own-object "
                           f"baseline {base_resp.status_code}")]
    baseline_text = base_resp.text or ""
    if MASS_PROBE_VALUE in baseline_text:
        return [done(method=method,
                     notes="mass assignment skipped: probe value "
                           "already present in baseline")]
    out: List[MassAssignmentResult] = []
    for field_name in list(fields or [])[:2]:
        replay = _build_with_extra(shape, tester_headers, field_name,
                                   MASS_PROBE_VALUE)
        if replay is None:
            out.append(done(method=method, field_name=field_name,
                            notes="mass assignment skipped: field "
                                  "already bound or shape unsupported"))
            continue
        if scope is not None:
            try:
                allowed = bool(scope.active_test_allowed(
                    replay["url"]))
            except Exception:
                allowed = False
            if not allowed:
                out.append(done(method=method, field_name=field_name,
                                notes="mass assignment skipped: replay "
                                      "URL out of scope"))
                continue
        try:
            kwargs: Dict[str, Any] = {"headers": replay["headers"],
                                      "timeout": timeout}
            if replay.get("body"):
                kwargs["data"] = replay["body"]
            response = http.request(replay["method"], replay["url"],
                                    **kwargs)
        except BudgetExceeded:
            raise
        except Exception as exc:
            log.debug("mass-assignment replay %s %s failed: %s",
                      replay["method"], replay["url"], exc)
            out.append(done(method=method, field_name=field_name,
                            notes="mass assignment request failed "
                                  "without a response"))
            continue
        accepted = 200 <= response.status_code < 300
        from ..validation.differential import looks_like_edge_deny
        try:
            replay_edge = looks_like_edge_deny(
                response.status_code, response.text or "",
                getattr(response, "headers", None))
        except Exception:
            replay_edge = False
        if replay_edge:
            out.append(done(method=method, field_name=field_name,
                            status=response.status_code,
                            edge_denied=True,
                            notes="mass assignment hit edge/bot-wall "
                                  "infrastructure, not the app"))
            continue
        if not accepted:
            if 400 <= response.status_code < 500:
                out.append(done(
                    method=method, field_name=field_name,
                    status=response.status_code, verdict="tested_negative",
                    notes=(f"mass assignment denied ({tester_name}→"
                           f"{response.status_code}); own-object "
                           "baseline was 200 so the negative is genuine")))
            else:
                out.append(done(
                    method=method, field_name=field_name,
                    status=response.status_code,
                    notes="mass assignment inconclusive: replay "
                          f"{response.status_code} proves nothing"))
            continue
        try:
            check = http.get(read_url, headers=tester_headers,
                             timeout=timeout)
        except BudgetExceeded:
            raise
        except Exception as exc:
            log.debug("mass-assignment readback %s failed: %s",
                      read_url, exc)
            out.append(done(method=method, field_name=field_name,
                            status=response.status_code,
                            replay_accepted=True,
                            notes="mass assignment accepted but "
                                  "readback unavailable; candidate "
                                  "stands unverified"))
            continue
        if check.status_code == 200:
            text = check.text or ""
            if MASS_PROBE_VALUE in text and \
                    MASS_PROBE_VALUE not in baseline_text:
                out.append(done(
                    method=method, field_name=field_name,
                    status=response.status_code, replay_accepted=True,
                    readback="confirmed-persisted",
                    verdict="strong_candidate",
                    notes=(f"mass assignment: '{field_name}' persisted "
                           f"on '{tester_name}''s own object via "
                           f"{method}; confirm the field has privilege "
                           "impact before reporting")))
                break
        out.append(done(method=method, field_name=field_name,
                        status=response.status_code,
                        replay_accepted=True,
                        notes="mass assignment accepted but the probe "
                              "value did not persist; inconclusive"))
    return out
