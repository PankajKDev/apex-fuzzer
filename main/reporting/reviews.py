"""Operator review marks (false/true-positive feedback loop).

Researchers triage findings between runs and record verdicts in
``reviews.jsonl`` (one JSON object per line, author-edited):

  {"finding_id": "diff-abc123", "verdict": "false_positive",
   "reason": "login page HTML served with 200 to everyone"}

Stable finding IDs (``stable_finding_id``) make marks stick across
runs. False-positive marks suppress repeat probing of the exact
(test class, endpoint, parameter) triple; true-positive marks are
retained as evidence and surfaced in notes. Unknown verdicts and
malformed lines are ignored (never fail a scan).
"""
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ..discovery.url_normalizer import normalize_url
from ..logging_setup import get_logger

log = get_logger("reviews")

REVIEW_TRUE = "true_positive"
REVIEW_FALSE = "false_positive"
_KNOWN_VERDICTS = (REVIEW_TRUE, REVIEW_FALSE)

# Triple key: (test class, normalized endpoint URL, parameter name).
Triple = Tuple[str, str, str]

# Authorization-family classes are one gap for suppression purposes:
# operators write idor/bola/authz interchangeably, and finding sources
# vary the same way (idor-swap, graphql-bola, authz-matrix).
_AUTHZ_FAMILY = frozenset({"idor", "bola", "authz", "authz_matrix"})


def canonical_test_class(name) -> str:
    """One vocabulary for triple matching (authz family merged)."""
    norm = _norm(name).replace("-", "_")
    if norm in _AUTHZ_FAMILY:
        return "authz"
    return norm


def canonical_triple_url(url) -> str:
    """Triple endpoint key: normalized URL without query/fragment.

    Operators write bare endpoints while findings carry concrete
    query strings — both must meet on scheme://host/path.
    """
    from urllib.parse import urlsplit, urlunsplit
    try:
        parts = urlsplit(str(url or "").strip())
        netloc = parts.netloc.rsplit("@", 1)[-1].lower()
        scheme = (parts.scheme or "http").lower()
        path = parts.path or "/"
        return urlunsplit((scheme, netloc, path, "", ""))
    except (TypeError, ValueError):
        return str(url or "")


def _norm(text) -> str:
    return str(text or "").strip().lower()


class ReviewIndex:
    """Validated review marks with finding-ID and triple lookup."""

    def __init__(self):
        self.by_finding: Dict[str, Dict] = {}
        self.triples: Set[Triple] = set()

    def verdict_for_finding(self, finding_id: str) -> Optional[Dict]:
        return self.by_finding.get(str(finding_id or ""))

    def is_fp_triple(self, test_class: str, normalized_url: str,
                     parameter: str) -> bool:
        return (canonical_test_class(test_class),
                canonical_triple_url(normalized_url),
                _norm(parameter)) in self.triples

    def __len__(self) -> int:
        return len(self.by_finding)


def load_reviews(path) -> ReviewIndex:
    """Read reviews.jsonl; missing file → empty index (never an error)."""
    import json
    index = ReviewIndex()
    p = Path(path)
    if not p.exists():
        return index
    try:
        lines = p.read_text(errors="ignore").splitlines()
    except OSError as e:
        log.debug("reviews unreadable %s: %s", path, e)
        return index
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            log.warning("reviews: skipping malformed line")
            continue
        if not isinstance(entry, dict):
            continue
        verdict = _norm(entry.get("verdict"))
        if verdict not in _KNOWN_VERDICTS:
            log.warning("reviews: skipping unknown verdict %r",
                        entry.get("verdict"))
            continue
        finding_id = str(entry.get("finding_id", "") or "").strip()
        reason = str(entry.get("reason", "") or "")[:500]
        record = {"verdict": verdict, "reason": reason}
        if finding_id:
            index.by_finding[finding_id] = record
        triple = (canonical_test_class(entry.get("test_class")),
                  canonical_triple_url(entry.get("endpoint", "")),
                  _norm(entry.get("parameter")))
        if verdict == REVIEW_FALSE and triple[0] and triple[1]:
            index.triples.add(triple)
    return index


def resolve_finding_triples(index: ReviewIndex,
                            findings: List) -> int:
    """Link finding-ID marks to triples via a findings list.

    Lets operators mark by finding ID alone: the triple is recovered
    from the finding's source/class, endpoint, and parameter. Returns
    the number of newly linked FP triples.
    """
    added = 0
    for fid, record in index.by_finding.items():
        if record.get("verdict") != REVIEW_FALSE:
            continue
        for f in findings or []:
            try:
                if getattr(f, "id", None) != fid:
                    continue
                triple = (canonical_test_class(finding_test_class(f)),
                          canonical_triple_url(
                              getattr(f, "endpoint_url", "") or
                              getattr(f, "matched_at", "")),
                          _norm(getattr(f, "parameter", "")))
            except Exception:
                continue
            if triple[0] and triple[1] and triple not in index.triples:
                index.triples.add(triple)
                added += 1
    return added


def finding_test_class(finding) -> str:
    """Best-effort finding → test-class mapping for triple keys."""
    source = str(getattr(finding, "source", "") or "").lower()
    # Bare stored-XSS sources stay XSS; suffixed second-order sources
    # (sqli/cmdi/ssti/traversal/ssrf) fall through to the candidate
    # loop so each maps to its own class.
    if source in ("second-order", "second_order"):
        return "xss"
    for alias, mapped in (("differential", "authz"),
                          ("misconfig-host-header", "header_injection"),
                          ("oast", "ssrf")):
        if alias in source:
            return mapped
    for candidate in ("sqli", "xss", "cmdi", "ssrf", "ssti", "xxe",
                      "idor", "bola", "authz", "auth", "cors", "csrf",
                      "redirect", "websocket",
                      "traversal", "cache", "jwt", "header_injection",
                      "clickjacking", "info_disclosure",
                      "mass_assignment", "parameter_pollution",
                      "deserialization", "postmessage", "html"):
        if candidate in source or candidate.replace("_", "-") in source:
            return candidate
    tags = [str(t).lower() for t in
            (getattr(finding, "tags", None) or [])]
    for candidate in ("sqli", "xss", "cmdi", "ssrf", "ssti", "xxe",
                      "idor", "bola", "authz", "auth", "cors", "csrf",
                      "redirect", "websocket",
                      "traversal", "cache", "jwt", "header_injection",
                      "clickjacking", "info_disclosure",
                      "mass_assignment", "parameter_pollution",
                      "deserialization", "postmessage", "html"):
        dashed = candidate.replace("_", "-")
        if any(candidate in tag or dashed in tag for tag in tags):
            return candidate
    return ""


def fp_suppression_reason(f, test_class, reviews) -> str:
    """Why this finding must skip plugin re-validation, or "".

    Finding-ID marks stick across runs via stable IDs; triple
    marks catch findings whose IDs rotate per run (swap findings
    embed victim values). Either suppresses — the probe already
    ran and a human ruled it out.
    """
    if reviews is None:
        return ""
    mark = reviews.verdict_for_finding(getattr(f, "id", ""))
    if mark and mark.get("verdict") == "false_positive":
        reason = mark.get("reason", "")
        return (f"operator-marked false positive ({f.id})"
                + (f": {reason}" if reason else ""))
    cls = test_class or finding_test_class(f)
    url = normalize_url(getattr(f, "endpoint_url", "") or
                        getattr(f, "matched_at", "") or "")
    param = getattr(f, "parameter", "") or ""
    if cls and url and reviews.is_fp_triple(cls, url, param):
        return (f"operator-marked false positive "
                f"({canonical_test_class(cls)} "
                f"{canonical_triple_url(url)}::{param.strip().lower()})")
    return ""
