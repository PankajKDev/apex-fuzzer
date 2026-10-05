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
