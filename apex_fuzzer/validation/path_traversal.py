"""Safe path-traversal validation using an operator-provided marker file.

The validator never reads common system files. It is inert unless both a
relative marker path and its exact expected contents are configured, and it
tests only an observed GET query parameter on a Nuclei lead.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlsplit

from .base import Candidate, ValidationOutcome, Validator
from .mutate import _inject
from ..budgets import BudgetExceeded
from ..models import Confidence, ValidationStatus


_PATH_NAMES = {
    "file", "filename", "filepath", "path", "page", "template",
    "include", "inc", "document", "doc", "folder", "dir", "view",
    "download", "image", "src", "source", "resource",
}
_MAX_DEPTH = 6


class PathTraversalValidator(Validator):
    name = "path-traversal-marker"
    test_class = "path_traversal"

    def __init__(self, cfg, http, timeout: int = 10):
        super().__init__(cfg)
        self.http = http
        self.timeout = timeout

    def validate(self, candidate: Candidate) -> ValidationOutcome:
        marker_path = str(getattr(
            self.cfg.validation, "path_traversal_marker_path", "") or "").strip()
        marker_value = str(getattr(
            self.cfg.validation, "path_traversal_marker_content", "") or "")
        valid_path, normalized_path = self._safe_marker_path(marker_path)
        if not valid_path or len(marker_value) < 8 or any(
                ord(char) < 32 or ord(char) == 127 for char in marker_value):
            return self._inconclusive(
                "configure a harmless relative marker path and its exact "
                "content (at least 8 characters) before path testing")

        method = (candidate.method or "GET").upper()
        if method != "GET" or candidate.parameter_location != "query":
            return self._inconclusive(
                "marker-based path checks support observed GET query fields")
        try:
            query = parse_qsl(urlsplit(candidate.endpoint_url).query,
                              keep_blank_values=True)
        except (TypeError, ValueError):
            query = []
        observed_names = {name for name, _ in query}
        parameter = candidate.parameter
        if not parameter:
            likely = sorted(name for name in observed_names
                            if name.lower() in _PATH_NAMES)
            parameter = likely[0] if likely else None
        if not parameter or parameter not in observed_names:
            return self._inconclusive(
                "no observed path-like query parameter is available")

        try:
            configured_depth = int(getattr(
                self.cfg.validation, "path_traversal_max_depth", 4))
        except (TypeError, ValueError):
            return self._inconclusive("path traversal depth cap is invalid")
        maximum = min(max(0, configured_depth), _MAX_DEPTH)
        if maximum == 0:
            return self._inconclusive("path traversal depth cap is zero")
        headers = dict(candidate.request_headers or {})
        responses: List[Dict[str, Any]] = []
        for depth in range(1, maximum + 1):
            payload = "../" * depth + normalized_path
            url = _inject(candidate.endpoint_url, parameter, payload)
            try:
                response = self.http.get(url, headers=headers,
                                         timeout=self.timeout)
            except BudgetExceeded:
                raise
            except Exception as exc:
                return self._inconclusive(
                    f"marker probe stopped after {len(responses)} request(s): "
                    f"{type(exc).__name__}",
                    {"parameter": parameter, "responses": responses})
            body = str(getattr(response, "text", "") or "")
            status = int(getattr(response, "status_code", 0) or 0)
            responses.append({"depth": depth, "status": status,
                              "body_length": len(body)})
            if marker_value in body:
                return ValidationOutcome(
                    status=ValidationStatus.CONFIRMED.value,
                    confidence=Confidence.CONFIRMED.value,
                    evidence={"parameter": parameter,
                              "marker_path": normalized_path,
                              "depth": depth, "response_status": status,
                              "response_body_recorded": False,
                              "requests_sent": len(responses)},
                    notes=("the operator-configured harmless marker contents "
                           "were read through the observed path parameter"))

        return self._inconclusive(
            "configured marker was not observed; traversal is not ruled out "
            "for other paths or depths",
            {"parameter": parameter, "marker_path": normalized_path,
             "responses": responses})

    @staticmethod
    def _safe_marker_path(value: str):
        if (not value or "\\" in value or "?" in value or "#" in value
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            return False, ""
        path = PurePosixPath(value)
        if (path.is_absolute() or not path.parts
                or any(part in ("", ".", "..") for part in path.parts)):
            return False, ""
        normalized = str(path)
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", normalized):
            return False, ""
        return True, normalized

    @staticmethod
    def _inconclusive(note: str,
                      evidence: Dict[str, Any] | None = None
                      ) -> ValidationOutcome:
        return ValidationOutcome(
            status=ValidationStatus.INCONCLUSIVE.value,
            confidence=Confidence.UNKNOWN.value,
            evidence=evidence or {}, notes=note)
