"""AI hypothesis planner — structured in/out, never declares vulns."""
import json
import os
from typing import List, Dict
from ..models import Hypothesis
from ..logging_setup import get_logger

log = get_logger("ai")


class AIPlanner:
    def __init__(self, cfg):
        self.cfg = cfg
        self.key = os.environ.get("GEMINI_API_KEY")

    def available(self) -> bool:
        return bool(self.cfg.ai.enabled and self.key)

    def _call(self, prompt: str, timeout: int = 30) -> str:
        import requests
        try:
            r = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/"
                f"models/{self.cfg.ai.model}:generateContent?key={self.key}",
                json={"contents": [{"parts": [{"text": prompt}]}],
                      "generationConfig": {
                          "maxOutputTokens": self.cfg.ai.max_output_tokens,
                          "responseMimeType": "application/json"}},
                timeout=timeout)
            data = r.json()
            if "error" in data:
                log.warning("AI error: %s", data["error"].get("message"))
                return ""
            cands = data.get("candidates") or []
            if not cands:
                return ""
            return cands[0]["content"]["parts"][0]["text"]
        except Exception as e:
            log.warning("AI call failed: %s", e)
            return ""

    def generate_hypotheses(self, technologies: List[Dict],
                            endpoints: List[Dict],
                            findings: List[Dict]) -> List[Hypothesis]:
        if not self.available():
            return []
        context = {
            "technologies": technologies[:40],
            "endpoint_sample": self._chunk_endpoints(endpoints),
            # group by host + vuln class instead of a raw char slice, so
            # one chatty host can't eat the whole prompt budget
            "findings": self._chunk_findings(findings),
        }
        prompt = (
            "You are an authorized security assessment analyst.\n"
            "Given the structured context, produce JSON hypotheses.\n"
            "Rules:\n"
            " - Never declare a vulnerability as confirmed.\n"
            " - Classify every item as: observed | inferred | hypothesized.\n"
            " - test_class must be one of: sqli, xss, ssrf, ssti, "
            "path_traversal, open_redirect, idor, authz, xxe, cmdi, "
            "info_disclosure.\n"
            " - required_context must be: unauthenticated | user | admin.\n"
            "Respond with a JSON array of objects with keys: "
            "hypothesis, endpoint, reason, test_class, confidence (0-1), "
            "required_context, status.\n\n"
            f"CONTEXT:\n{self._bounded_json(context)}")
        return self._parse(self._call(prompt))

    def plan_js_chunk(self, js_url: str, chunk: str) -> List[Hypothesis]:
        """Feed one structurally-chunked JS slice to the planner (spec §6).

        Full SPAs ship 500KB–2MB bundles; chunking on structural
        boundaries (modules, functions) and sending each chunk
        separately keeps every route/param/secret in scope instead of
        silently truncating the bundle header.
        """
        if not self.available() or not chunk:
            return []
        prompt = (
            "You are an authorized security assessment analyst.\n"
            "Below is a chunk of a first-party JavaScript bundle from "
            f"{js_url}.\n"
            "Find: hidden API endpoints/paths, parameter names, "
            "authentication/authorization logic, secrets, and "
            "SSRF/redirect/file parameters.\n"
            "Rules:\n"
            " - Never declare a vulnerability as confirmed.\n"
            " - test_class must be one of: sqli, xss, ssrf, ssti, "
            "path_traversal, open_redirect, idor, authz, xxe, cmdi, "
            "info_disclosure.\n"
            " - endpoint may be a path (e.g. /api/users) or a URL.\n"
            "Respond with a JSON array of objects with keys: "
            "hypothesis, endpoint, reason, test_class, confidence (0-1), "
            "required_context, status.\n\n"
            f"JS CHUNK:\n{chunk[:12000]}")
        return self._parse(self._call(prompt, timeout=60))

    @staticmethod
    def _bounded_json(context: Dict, total: int = 14000) -> str:
        """JSON-dump context with per-part caps so no single part can
        truncate everything after it."""
        parts = []
        for key, cap in (("technologies", 2000),
                         ("endpoint_sample", 6000),
                         ("findings", 4000)):
            val = context.get(key) or []
            if not isinstance(val, list):
                val = [val]
            s = json.dumps(val)
            while len(s) > cap and len(val) > 1:
                val = val[:max(1, len(val) // 2)]
                s = json.dumps(val)
            parts.append(f"{key}: {s}")
        return "\n".join(parts)[:total]

    def _chunk_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        seen, out = set(), []
        for e in endpoints:
            key = (e.get("host"), e.get("endpoint_type"))
            if key in seen and len(out) > 200:
                continue
            seen.add(key)
            out.append({"host": e.get("host"), "path": e.get("path"),
                        "type": e.get("endpoint_type"),
                        "params": [p.get("name") for p in
                                   (e.get("query_parameters") or [])][:10]})
            if len(out) >= 400:
                break
        return out

    def _chunk_findings(self, findings: List[Dict]) -> List[Dict]:
        # group by host + vuln class; cap each group so one noisy
        # host/class can't dominate the prompt
        by_key: Dict[tuple, List] = {}
        for f in findings:
            from urllib.parse import urlparse
            host = (urlparse(f.get("matched_at", "")).hostname
                    or f.get("host", ""))
            cls = f.get("template_id", "other").split("-")[0]
            by_key.setdefault((host, cls), []).append(
                {"severity": f.get("severity"), "url": f.get("matched_at")})
        out: List[Dict] = []
        for (host, cls), items in by_key.items():
            for item in items[:10]:
                out.append({"host": host, "class": cls, **item})
            if len(out) >= 150:
                return out
        return out

    def _parse(self, raw: str) -> List[Hypothesis]:
        if not raw:
            return []
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.startswith("json"):
                raw = raw[4:]
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("AI returned non-JSON; discarding")
            return []
        if isinstance(data, dict):
            data = data.get("hypotheses", [])
        out = []
        for item in data:
            if not isinstance(item, dict):
                continue
            out.append(Hypothesis(
                hypothesis=str(item.get("hypothesis", ""))[:500],
                endpoint=item.get("endpoint"),
                reason=str(item.get("reason", ""))[:500],
                test_class=str(item.get("test_class", "unknown")),
                confidence=float(item.get("confidence", 0.0) or 0.0),
                required_context=str(item.get("required_context",
                                              "unauthenticated")),
                status=str(item.get("status", "hypothesized"))))
        return out
