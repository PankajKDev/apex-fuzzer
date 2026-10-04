"""Built-in plugins: thin adapters over the existing validators.

These change *how* engines are invoked (registry + TestResult), not
*what* they do. Preserved semantics from the pre-plugin loop:

- mutation prescreen runs before the heavy validator of the same class;
- a prescreen hit does NOT suppress the heavy validator — when available it
  runs too, and per-finding aggregation combines both outcomes;
- each tool's evidence is retained; conflicting positive and negative
  results resolve to inconclusive instead of last-write-wins.
"""
from typing import Optional, Tuple
from .base import (SecurityTest, TestTarget, TestContext, register)


def _cookie_pairs(headers) -> list:
    """Cookie pairs from a header mapping (best-effort, never raises)."""
    if not isinstance(headers, dict):
        return []
    for name, value in headers.items():
        if isinstance(name, str) and name.strip().lower() == "cookie" \
                and isinstance(value, str):
            pairs = []
            for chunk in value.split(";"):
                chunk = chunk.strip()
                if not chunk or '"' in chunk:
                    continue
                pname, sep, pvalue = chunk.partition("=")
                if sep and pname.strip():
                    pairs.append((pname.strip(), pvalue.strip()))
            return pairs
    return []
from ..budgets import BudgetExceeded
from ..models import (TestResult, RESULT_CONFIRMED, RESULT_CANDIDATE,
                      RESULT_NEGATIVE, RESULT_INCONCLUSIVE,
                      ValidationStatus)
from ..validation.base import Candidate
from ..validation.mutate import MutationEngine
from ..validation.sqli import SqliValidator
from ..validation.xss import XssValidator
from ..validation.ssrf import SsrfValidator
from ..validation.ssti import SstiValidator
from ..validation.xxe import XxeValidator
from ..validation.path_traversal import PathTraversalValidator


def _candidate_from(target: TestTarget, test_class: str,
                    scope=None) -> Candidate:
    from urllib.parse import parse_qsl, urlsplit
    endpoint = target.endpoint
    body_parameters = list(getattr(endpoint, "body_parameters", []) or [])
    parameter = target.parameter
    in_body = parameter and any(
        getattr(p, "name", "") == parameter for p in body_parameters)
    in_request_query = parameter and any(
        name == parameter for name, _ in parse_qsl(
            urlsplit(target.endpoint_url).query, keep_blank_values=True))
    header_parameters = list(getattr(endpoint, "header_parameters", [])
                             or []) if endpoint is not None else []
    in_header = parameter and any(
        getattr(p, "name", "").lower() == parameter.lower()
        for p in header_parameters)
    finding_headers = dict(getattr(target.finding, "request_headers",
                                     {}) or {})
    in_cookie = parameter and any(
        name.strip().lower() == parameter.strip().lower()
        for name, _ in _cookie_pairs(finding_headers))
    if in_body and not in_request_query:
        location = "body"
    elif in_header and not in_request_query and not in_body:
        location = "header"
    elif in_cookie and not in_request_query and not in_body \
            and not in_header:
        location = "cookie"
    else:
        location = "query"
    content_types = list(getattr(endpoint, "request_content_types", []) or [])
    content_type = ((content_types[0] if content_types else "") or
                    getattr(endpoint, "content_type", ""))
    finding = target.finding
    method = (target.method or "GET").upper()
    supported_methods = {"GET", "POST", "PUT", "PATCH", "DELETE",
                         "OPTIONS", "HEAD"}
    if method not in supported_methods:
        method = (getattr(endpoint, "method", "GET") or "GET").upper()
    candidate = Candidate(finding=target.finding, test_class=test_class,
                          endpoint_url=target.endpoint_url,
                          method=method,
                          parameter=parameter,
                          request_headers=dict(getattr(
                              finding, "request_headers", {}) or {}),
                          request_body=getattr(finding, "request_body", None),
                          parameter_location=location,
                          request_content_type=content_type,
                          body_parameters=body_parameters)
    if test_class in ("sqli", "xss"):
        _apply_observed_raw_request(candidate, finding)
        from ..validation.request_shape import (is_xml,
                                                xml_body_parameter_value)
        if is_xml(candidate) and isinstance(candidate.request_body, str):
            if candidate.parameter:
                try:
                    xml_body_parameter_value(candidate, candidate.parameter)
                    if not in_request_query:
                        candidate.parameter_location = "body"
                except ValueError:
                    pass
            elif len(body_parameters) == 1:
                name = getattr(body_parameters[0], "name", "")
                try:
                    xml_body_parameter_value(candidate, name)
                    candidate.parameter = name
                    candidate.parameter_location = "body"
                except ValueError:
                    pass
        _apply_observed_browser_request(candidate, endpoint, scope)
    return candidate


def _apply_observed_browser_request(candidate: Candidate, endpoint,
                                   scope=None) -> None:
    """Pin one retained browser request to a SQLi/XSS candidate, if safe.

    Uses ``Endpoint.observed_requests`` only when exactly one retained
    shape matches the in-scope endpoint and the already-selected
    candidate parameter. The candidate stays pinned to that parameter;
    ambiguous multi-request/multi-identity matches set
    ``observed_ambiguous`` so validators fail closed without guessing or
    fanning out. Never copies header/body values beyond the runtime
    candidate (evidence keeps only the identity name).
    """
    if endpoint is None or not candidate.parameter:
        return
    try:
        from ..validation.observed_sqli import select_observed_request
    except ImportError:
        return
    matched, reason = select_observed_request(
        endpoint, candidate.parameter, candidate.parameter_location,
        scope=scope, endpoint_url=candidate.endpoint_url)
    if matched is None:
        if reason.startswith(("ambiguous",
                              "unsupported observed request shape")):
            candidate.observed_ambiguous = reason
        return
    headers = matched.get("headers") or {}
    filtered = {}
    if isinstance(headers, dict):
        excluded = {"host", "content-length", "connection",
                    "transfer-encoding"}
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            if not name.strip() or name.strip().lower() in excluded:
                continue
            filtered[name.strip()] = value.strip()
    content_type = str(matched.get("content_type") or "")
    if not content_type:
        for name, value in filtered.items():
            if name.lower() == "content-type":
                content_type = str(value)
                break
    post_data = matched.get("post_data")
    body: object = None
    if isinstance(post_data, (bytes, bytearray)):
        try:
            body = bytes(post_data).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            candidate.observed_ambiguous = (
                "observed body is not UTF-8 text; fail closed "
                "without guessing")
            return
    elif isinstance(post_data, str):
        body = post_data
    elif post_data is None:
        body = None
    else:
        return
    identity = matched.get("identity", "anonymous")
    candidate.method = str(matched.get("method") or
                           candidate.method or "GET").upper()
    candidate.endpoint_url = str(matched.get("url") or
                                 candidate.endpoint_url)
    if filtered:
        candidate.request_headers = filtered
    if body is not None:
        candidate.request_body = body
    if content_type:
        candidate.request_content_type = content_type
    candidate.observed_request = dict(matched)
    candidate.observed_identity = str(identity or "anonymous")


def _apply_observed_raw_request(candidate: Candidate, finding) -> None:
    """Fill request metadata only from a raw request retained by Nuclei."""
    raw = getattr(finding, "raw", None)
    if not isinstance(raw, dict):
        return
    request = raw.get("request") or raw.get("request_raw")
    if not isinstance(request, str):
        return
    normalized = request.replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    if not separator:
        return
    lines = head.splitlines()
    first_line = lines[0].split() if lines else []
    if first_line and first_line[0].upper() in {"POST", "PUT", "PATCH"}:
        candidate.method = first_line[0].upper()
    captured_headers = {}
    excluded_headers = {"host", "content-length", "connection",
                        "transfer-encoding"}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        name = name.strip()
        if not name or name.lower() in excluded_headers:
            continue
        captured_headers[name] = value.strip()
        if name.lower() == "content-type":
            candidate.request_content_type = value.strip()
    if not candidate.request_headers:
        candidate.request_headers = captured_headers
    if not candidate.request_body and body:
        candidate.request_body = body


def _xxe_candidate_from(target: TestTarget) -> Candidate:
    """Use raw observed XML request material when Nuclei retained it."""
    candidate = _candidate_from(target, "xxe")
    finding = target.finding
    raw = getattr(finding, "raw", None)
    if not isinstance(raw, dict):
        return candidate
    request = raw.get("request") or raw.get("request_raw")
    if not isinstance(request, str):
        return candidate
    normalized = request.replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    if not separator:
        return candidate
    first_line = head.splitlines()[0].split()
    methods = {"POST", "PUT", "PATCH"}
    if first_line and first_line[0].upper() in methods:
        candidate.method = first_line[0].upper()
    if body.strip():
        candidate.request_body = body.strip()
    for line in head.splitlines()[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "content-type":
            candidate.request_content_type = value.strip()
            break
    return candidate


class _ClassGated(SecurityTest):
    handled_classes: Tuple[str, ...] = ()
    allocates_evidence = True

    def _class_ok(self, target: TestTarget) -> Optional[TestResult]:
        cls = (target.test_class or "unknown").lower()
        if self.handled_classes and cls not in self.handled_classes:
            return TestResult(status="skipped",
                              observations=[f"class {cls} not handled"])
        return None


def _from_sqli_mutation(outcome) -> TestResult:
    if outcome is None:
        return TestResult(status="skipped",
                          observations=["no mutation signal"])
    if outcome.status == ValidationStatus.CONFIRMED.value:
        st = RESULT_CONFIRMED
    elif outcome.status == ValidationStatus.STRONG_CANDIDATE.value:
        st = RESULT_CANDIDATE
    elif outcome.status == ValidationStatus.FALSE_POSITIVE.value:
        st = RESULT_NEGATIVE
    else:
        st = RESULT_INCONCLUSIVE
    return TestResult(status=st, evidence=dict(outcome.evidence or {}),
                      observations=[outcome.notes or ""])


class SqliMutationPlugin(_ClassGated):
    name = "sqli-mutation"
    handled_classes = ("sqli",)
    prerequisites = ("net",)
    allocates_evidence = False

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        if not ctx.cfg.validation.mutation:
            return TestResult(status="skipped",
                              observations=["mutation engine disabled"])
        if ctx.scope is not None and not ctx.scope.active_test_allowed(
                target.endpoint_url):
            return TestResult(status="blocked",
                              observations=["target is not active-test "
                                            "eligible"])
        engine = MutationEngine(ctx.cfg, ctx.http, ctx.waf)
        try:
            outcome = engine.prescreen_sqli(
                _candidate_from(target, "sqli", scope=ctx.scope))
        except BudgetExceeded as exc:
            return TestResult(status="blocked",
                              observations=[str(exc)[:300]])
        return _from_sqli_mutation(outcome)


class SqliPlugin(_ClassGated):
    name = "sqli-sqlmap"
    handled_classes = ("sqli",)
    prerequisites = ("net", "tool:sqlmap")

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        if ctx.scope is not None and not ctx.scope.active_test_allowed(
                target.endpoint_url):
            return TestResult(status="blocked",
                              observations=["target is not active-test "
                                            "eligible"])
        # One sqlmap run per finding; observed selection never fans out
        # across identities (ambiguous captures fail closed upstream).
        outcome = SqliValidator(ctx.cfg).validate(
            _candidate_from(target, "sqli", scope=ctx.scope),
            budgets=ctx.budgets)
        if "vulnerable" in (outcome.notes or "").lower() or \
                outcome.status == ValidationStatus.CONFIRMED.value:
            st = RESULT_CONFIRMED
        elif outcome.status == ValidationStatus.FALSE_POSITIVE.value:
            st = RESULT_NEGATIVE
        else:
            st = RESULT_INCONCLUSIVE
        return TestResult(status=st, evidence=dict(outcome.evidence or {}),
                          observations=[outcome.notes or ""])


class XssMutationPlugin(_ClassGated):
    name = "xss-mutation"
    handled_classes = ("xss",)
    prerequisites = ("net",)
    allocates_evidence = False

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        if not ctx.cfg.validation.mutation:
            return TestResult(status="skipped",
                              observations=["mutation engine disabled"])
        if ctx.scope is not None and not ctx.scope.active_test_allowed(
                target.endpoint_url):
            return TestResult(status="blocked",
                              observations=["target is not active-test "
                                            "eligible"])
        engine = MutationEngine(ctx.cfg, ctx.http, ctx.waf)
        try:
            outcome = engine.prescreen_xss(
                _candidate_from(target, "xss", scope=ctx.scope))
        except BudgetExceeded as exc:
            return TestResult(status="blocked",
                              observations=[str(exc)[:300]])
        return _from_sqli_mutation(outcome)


class XssPlugin(_ClassGated):
    name = "xss-dalfox"
    handled_classes = ("xss",)
    prerequisites = ("net", "tool:dalfox")

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        if ctx.scope is not None and not ctx.scope.active_test_allowed(
                target.endpoint_url):
            return TestResult(status="blocked",
                              observations=["target is not active-test "
                                            "eligible"])
        outcome = XssValidator(
            ctx.cfg, browser_enabled=ctx.browser_enabled).validate(
            _candidate_from(target, "xss", scope=ctx.scope))
        if outcome.status == ValidationStatus.CONFIRMED.value:
            st = RESULT_CONFIRMED
        elif outcome.status == ValidationStatus.STRONG_CANDIDATE.value:
            st = RESULT_CANDIDATE
        elif outcome.status == ValidationStatus.FALSE_POSITIVE.value:
            st = RESULT_NEGATIVE
        else:
            st = RESULT_INCONCLUSIVE
        return TestResult(status=st, evidence=dict(outcome.evidence or {}),
                          observations=[outcome.notes or ""])


class SsrfPlugin(_ClassGated):
    name = "ssrf-oast"
    handled_classes = ("ssrf",)
    prerequisites = ("net", "oast")

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        outcome = SsrfValidator(ctx.cfg, ctx.oast_provider,
                                ctx.http).validate(
            _candidate_from(target, "ssrf"))
        if outcome.status == ValidationStatus.CONFIRMED.value:
            st = RESULT_CONFIRMED
        else:
            st = RESULT_INCONCLUSIVE
        return TestResult(status=st, evidence=dict(outcome.evidence or {}),
                          observations=[outcome.notes or ""])


class SstiPlugin(_ClassGated):
    name = "ssti-arithmetic"
    handled_classes = ("ssti",)
    prerequisites = ("net",)

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        if not ctx.cfg.validation.ssti:
            return TestResult(status="skipped",
                              observations=["SSTI validator disabled"])
        try:
            outcome = SstiValidator(ctx.cfg, ctx.http, ctx.timeout).validate(
                _candidate_from(target, "ssti"))
        except BudgetExceeded as exc:
            return TestResult(status="blocked", observations=[str(exc)[:300]])
        if outcome.status == ValidationStatus.CONFIRMED.value:
            status = RESULT_CONFIRMED
        elif outcome.status == ValidationStatus.STRONG_CANDIDATE.value:
            status = RESULT_CANDIDATE
        else:
            status = RESULT_INCONCLUSIVE
        return TestResult(status=status, evidence=dict(outcome.evidence or {}),
                          observations=[outcome.notes or ""])


class XxePlugin(_ClassGated):
    name = "xxe-oast"
    handled_classes = ("xxe",)
    prerequisites = ("net", "oast")

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        if not ctx.cfg.validation.xxe:
            return TestResult(status="skipped",
                              observations=["XXE validator disabled"])
        if ctx.scope and not ctx.scope.active_test_allowed(target.endpoint_url):
            return TestResult(status="blocked",
                              observations=["target is not active-test eligible"])
        try:
            outcome = XxeValidator(
                ctx.cfg, ctx.http, ctx.oast_provider, ctx.timeout).validate(
                    _xxe_candidate_from(target))
        except BudgetExceeded as exc:
            return TestResult(status="blocked", observations=[str(exc)[:300]])
        if outcome.status == ValidationStatus.CONFIRMED.value:
            status = RESULT_CONFIRMED
        elif outcome.status == ValidationStatus.STRONG_CANDIDATE.value:
            status = RESULT_CANDIDATE
        else:
            status = RESULT_INCONCLUSIVE
        return TestResult(status=status, evidence=dict(outcome.evidence or {}),
                          observations=[outcome.notes or ""])


class PathTraversalPlugin(_ClassGated):
    name = "path-traversal-marker"
    handled_classes = ("path_traversal",)
    prerequisites = ("net",)

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        if not ctx.cfg.validation.path_traversal:
            return TestResult(status="skipped",
                              observations=["path traversal validator disabled"])
        if ctx.scope and not ctx.scope.active_test_allowed(target.endpoint_url):
            return TestResult(status="blocked",
                              observations=["target is not active-test eligible"])
        try:
            outcome = PathTraversalValidator(
                ctx.cfg, ctx.http, ctx.timeout).validate(
                    _candidate_from(target, "path_traversal"))
        except BudgetExceeded as exc:
            return TestResult(status="blocked", observations=[str(exc)[:300]])
        if outcome.status == ValidationStatus.CONFIRMED.value:
            status = RESULT_CONFIRMED
        elif outcome.status == ValidationStatus.STRONG_CANDIDATE.value:
            status = RESULT_CANDIDATE
        else:
            status = RESULT_INCONCLUSIVE
        return TestResult(status=status, evidence=dict(outcome.evidence or {}),
                          observations=[outcome.notes or ""])


for _p in (SqliMutationPlugin(), SqliPlugin(), XssMutationPlugin(),
           XssPlugin(), SsrfPlugin(), SstiPlugin(), XxePlugin(),
           PathTraversalPlugin()):
    register(_p)

# fixed execution order: prescreen before heavy tool, same class grouped
PLUGIN_ORDER = ["sqli-mutation", "sqli-sqlmap", "xss-mutation",
                "xss-dalfox", "ssrf-oast", "ssti-arithmetic", "xxe-oast",
                "path-traversal-marker"]
