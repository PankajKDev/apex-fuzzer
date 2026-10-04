"""SQLi validation adapter (maintained sqlmap engine, bounded profile)."""
import os
import re
import tempfile
from .base import Validator, Candidate, ValidationOutcome
from ..shell import run, which, redact
from ..models import ValidationStatus, Confidence


# sqlmap result signals across versions: 1.8.x reports e.g.
# "GET parameter 'id' is '... blind' injectable" on success and
# "does not seem to be injectable" / "do not appear to be injectable"
# on failure. Newer releases also print "is vulnerable".
_SQLMAP_SUCCESS_RE = re.compile(
    r"is vulnerable|is '[^']+' injectable|is \"[^\"]+\" injectable", re.I)
_SQLMAP_NEGATIVE_RE = re.compile(
    r"not injectable|does not seem to be injectable|"
    r"do not appear to be injectable", re.I)


def _sqlmap_success(text: str) -> bool:
    return bool(text and _SQLMAP_SUCCESS_RE.search(text))


def _sqlmap_negative(text: str) -> bool:
    return bool(text and _SQLMAP_NEGATIVE_RE.search(text))


def _inconclusive(notes: str) -> ValidationOutcome:
    return ValidationOutcome(
        status=ValidationStatus.INCONCLUSIVE.value,
        confidence=Confidence.UNKNOWN.value,
        evidence={},
        notes=notes)


class SqliValidator(Validator):
    name = "sqlmap"
    test_class = "sqli"

    def _technique(self) -> str:
        """BEU by default; T joins only under explicit time opt-in."""
        if getattr(getattr(self.cfg, "validation", None),
                   "sqli_time_based", False):
            return "BEUT"
        return "BEU"

    def _time_sec(self) -> int:
        try:
            seconds = int(getattr(getattr(self.cfg, "validation", None),
                                  "sqli_time_sec", 2))
        except (TypeError, ValueError):
            return 2
        return max(1, min(seconds, 10))

    def _technique_label(self) -> str:
        if getattr(getattr(self.cfg, "validation", None),
                   "sqli_time_based", False):
            return "boolean/error/union/time-based"
        return "boolean/error/union-based"

    def can_handle(self, candidate: Candidate) -> bool:
        return candidate.test_class == "sqli" and which("sqlmap") is not None

    def validate(self, candidate: Candidate, budgets=None) -> ValidationOutcome:
        from urllib.parse import parse_qsl, urlsplit
        from .request_shape import (body_with_parameter, encode_form,
                                    encode_json, is_json, is_multipart,
                                    is_xml)

        if getattr(candidate, "observed_ambiguous", None):
            return _inconclusive(
                "sqlmap skipped: " +
                str(candidate.observed_ambiguous)[:300])
        if (candidate.parameter_location or "query").lower() in (
                "header", "cookie"):
            return _inconclusive(
                "sqlmap skipped: header/cookie inputs are prescreen-only; "
                "sqlmap's bounded profile tests query/body parameters")
        observed = getattr(candidate, "observed_request", None)
        if isinstance(observed, dict):
            return self._validate_observed(candidate, observed, budgets)

        method = (candidate.method or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH"}:
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={},
                notes=f"sqlmap skipped: unsupported method {method}")
        if method != "GET" and not getattr(
                getattr(self.cfg, "safety", None), "allow_state_change", False):
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={},
                notes="sqlmap body probes skipped: state-changing requests "
                      "require allow_state_change")
        if candidate.parameter_location == "body" and method == "GET":
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={},
                notes="sqlmap skipped: GET body shape is unsupported")
        if (candidate.parameter_location == "body" and is_xml(candidate)):
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={},
                notes="sqlmap XML request replay is unsupported; exact raw "
                      "headers/body cannot be preserved safely")
        if candidate.parameter_location == "body" and is_multipart(candidate):
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={},
                notes="sqlmap multipart request replay is unimplemented; "
                      "no file upload is sent")

        param = candidate.parameter
        if not param and candidate.parameter_location != "body":
            query_params = parse_qsl(urlsplit(candidate.endpoint_url).query,
                                     keep_blank_values=True)
            param = query_params[-1][0] if query_params else None
        if not param:
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={},
                notes="sqlmap skipped: no candidate parameter was identified")

        out_dir = getattr(candidate.finding, "evidence_dir", None) or \
            "/tmp/sqlmap"
        # Boolean + error + UNION by default; time-based joins only under
        # explicit opt-in (delay payloads hold DB connections open).
        # Stacked queries stay excluded (possible writes).
        args = [
            "sqlmap", "-u", candidate.endpoint_url, "--batch",
            "-p", param, "--level", "1", "--risk", "1",
            "--technique", self._technique(),
            f"--output-dir={out_dir}", "--timeout", "10",
            "--retries", "0", "--threads", "1",
        ]
        if "T" in self._technique():
            args.extend(["--time-sec", str(self._time_sec())])
        if method != "GET":
            args.extend(["--method", method])
        if candidate.parameter_location == "body":
            try:
                body = body_with_parameter(
                    candidate, param, self._body_sample(candidate, param))
            except ValueError as exc:
                return _inconclusive(
                    f"sqlmap skipped: request shape cannot be built "
                    f"safely ({exc})")
            args.extend(["--data", encode_json(body) if is_json(candidate)
                         else encode_form(body)])
            if is_json(candidate):
                args.extend(["--headers", "Content-Type: application/json"])
        if budgets is not None and not self._admit_external_request(
                candidate, budgets):
            return _inconclusive(
                "sqlmap skipped: shared request budget exhausted before "
                "external validation")
        r = run(args, timeout=180)
        log_text = redact((r.stdout or "") + (r.stderr or ""))
        if _sqlmap_success(log_text):
            return ValidationOutcome(
                status=ValidationStatus.CONFIRMED.value,
                confidence=Confidence.CONFIRMED.value,
                evidence={"sqlmap_tail": log_text[-2000:],
                          "parameter": param,
                          "techniques": self._technique_label()},
                notes="sqlmap reported a confirmed injection point on "
                      f"parameter {param!r}")
        if _sqlmap_negative(log_text):
            return ValidationOutcome(
                status=ValidationStatus.FALSE_POSITIVE.value,
                confidence=Confidence.PROBABLE.value,
                evidence={"sqlmap_tail": log_text[-1000:]},
                notes="sqlmap reports parameter is not injectable")
        return ValidationOutcome(
            status=ValidationStatus.INCONCLUSIVE.value,
            confidence=Confidence.UNKNOWN.value,
            evidence={"sqlmap_tail": log_text[-1000:]},
            notes="sqlmap finished without a definitive result")

    def _validate_observed(self, candidate: Candidate,
                           observed: dict, budgets=None) -> ValidationOutcome:
        """Run sqlmap once against an exact retained request via ``-r``.

        The candidate stays pinned to its single parameter. Anything that
        cannot be represented faithfully as text (multipart, binary,
        oversized, malformed) is inconclusive without sending. The raw
        request and sqlmap output directory live in a private temporary
        directory that is removed after the run; free-form sqlmap output is
        inspected for a result signal but never persisted in findings.
        """
        from .observed_sqli import (redact_url, serialize_observed_to_raw,
                                    sqlmap_args_for_raw)
        param = candidate.parameter
        if not param:
            return _inconclusive(
                "sqlmap skipped: no candidate parameter was identified")
        method = (candidate.method or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH"}:
            return _inconclusive(
                f"sqlmap skipped: unsupported method {method}")
        if candidate.parameter_location == "body" and method == "GET":
            return _inconclusive(
                "sqlmap skipped: GET body shape is unsupported")
        if method != "GET" and not getattr(
                getattr(self.cfg, "safety", None), "allow_state_change",
                False):
            return _inconclusive(
                "sqlmap body probes skipped: state-changing requests "
                "require allow_state_change")
        identity = getattr(candidate, "observed_identity", None) or \
            str((observed.get("identity") or "anonymous"))
        from .observed_sqli import (_body_has_parameter, _content_type_of,
                                    _post_data_text, _query_has_parameter)
        location = (candidate.parameter_location or "query").lower()
        if location == "query":
            if not _query_has_parameter(str(observed.get("url") or ""),
                                        param):
                return _inconclusive(
                    f"sqlmap skipped: parameter {param!r} is absent from "
                    f"the observed URL (identity {identity}; no request "
                    f"sent)")
        else:
            body_text, problem = _post_data_text(observed.get("post_data"))
            if problem or not _body_has_parameter(
                    _content_type_of(observed), body_text, param):
                return _inconclusive(
                    f"sqlmap skipped: parameter {param!r} is absent from "
                    f"the observed body (identity {identity}; no request "
                    f"sent)")
        try:
            raw_text = serialize_observed_to_raw(observed)
        except ValueError as exc:
            return _inconclusive(
                f"sqlmap skipped: {exc} for parameter {param!r} "
                f"(identity {identity}; no request sent)")
        try:
            if budgets is not None and not self._admit_external_request(
                    candidate, budgets):
                return _inconclusive(
                    "sqlmap skipped: shared request budget exhausted before "
                    "external validation")
            with tempfile.TemporaryDirectory(
                    prefix="apex-sqlmap-") as private_dir:
                os.chmod(private_dir, 0o700)
                handle = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".req", dir=private_dir,
                    delete=False, encoding="utf-8")
                raw_path = handle.name
                try:
                    os.chmod(raw_path, 0o600)
                    with handle:
                        handle.write(raw_text)
                    args = sqlmap_args_for_raw(
                        raw_path, param, private_dir,
                        time_based="T" in self._technique(),
                        time_sec=self._time_sec())
                    r = run(args, timeout=180)
                finally:
                    if not handle.closed:
                        handle.close()
        except OSError:
            return _inconclusive(
                "sqlmap skipped: could not create private temporary request "
                "artifacts; no credentials or body were persisted")

        # sqlmap output can echo request headers, cookies, parameter values,
        # or response fragments. Inspect it only for the bounded success
        # signals; do not persist its free-form output in evidence.
        log_text = (r.stdout or "") + (r.stderr or "")
        base_evidence = {"sqlmap_signal": "",
                         "parameter": param,
                         "techniques": self._technique_label(),
                         "request_shape": "observed-raw",
                         "observed_identity": identity,
                         "observed_method": method,
                         "endpoint_url": redact_url(
                             candidate.endpoint_url)}
        if _sqlmap_success(log_text):
            base_evidence["sqlmap_signal"] = "is vulnerable"
            return ValidationOutcome(
                status=ValidationStatus.CONFIRMED.value,
                confidence=Confidence.CONFIRMED.value,
                evidence=base_evidence,
                notes="sqlmap reported a confirmed injection point on "
                      f"parameter {param!r} using the retained "
                      f"{method} request (identity {identity})")
        if _sqlmap_negative(log_text):
            base_evidence["sqlmap_signal"] = "not injectable"
            return ValidationOutcome(
                status=ValidationStatus.FALSE_POSITIVE.value,
                confidence=Confidence.PROBABLE.value,
                evidence=base_evidence,
                notes="sqlmap reports parameter is not injectable "
                      f"(identity {identity})")
        base_evidence["sqlmap_signal"] = "no definitive signal"
        return ValidationOutcome(
            status=ValidationStatus.INCONCLUSIVE.value,
            confidence=Confidence.UNKNOWN.value,
            evidence=base_evidence,
            notes="sqlmap finished without a definitive result "
                  f"(identity {identity})")

    @staticmethod
    def _admit_external_request(candidate: Candidate, budgets) -> bool:
        """Account for one sqlmap validation before launching the process.

        sqlmap has no packet-count cap, so the shared tracker can account for
        admission and state-change intent, but cannot meter each internal
        request. The caller must retain the low-risk argv and process timeout.
        """
        from urllib.parse import urlsplit
        try:
            host = urlsplit(candidate.endpoint_url).hostname or ""
        except (TypeError, ValueError):
            host = ""
        if (candidate.method or "GET").upper() != "GET":
            return budgets.consume_mutation(host, candidate.endpoint_url)
        return budgets.consume_request(host, candidate.endpoint_url)

    @staticmethod
    def _body_sample(candidate: Candidate, parameter: str) -> str:
        from .request_shape import body_parameter_value
        return body_parameter_value(candidate, parameter)
