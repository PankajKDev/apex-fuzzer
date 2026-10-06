"""First-party JS intelligence: feature flags, admin routes, flag SDKs.

Pure offline extractors over cached bundle text (no network, no
execution). Feature flags gate hidden functionality — knowing their
names shapes differential and authz follow-ups. Admin-route strings
are unverified client-side hints: they become leads for manual
verification, never endpoints (a client route may not exist
server-side). Flag SDK fingerprints explain where flags come from.
"""
import re
from typing import Any, Dict, List

# Literal flag reads: isEnabled("x"), useFlag('x'), flags.x, variation.
_FLAG_RES = [
    re.compile(r"""(?:isEnabled|isFeatureEnabled|useFlag|getFlag|
                    hasFeature|variation)\s*\(\s*["']([\w][\w\-]{1,60})["']""",
               re.X),
    re.compile(r"""(?:featureFlags|flags)\s*(?:\.\s*|\[\s*["'])
                    ([\w][\w\-]{1,60})""", re.X),
]

# SDK fingerprints (vendor client markers).
_SDK_RES = [
    ("launchdarkly", re.compile(r"launchdarkly|ldclient|LDClient", re.I)),
    ("unleash", re.compile(r"unleash", re.I)),
    ("flagsmith", re.compile(r"flagsmith", re.I)),
    ("statsig", re.compile(r"statsig", re.I)),
    ("optimizely", re.compile(r"optimizely", re.I)),
]

# Quoted absolute paths with a privileged segment.
_ADMIN_PATH_RE = re.compile(
    r"""["'](/+((?:admin|internal|debug|console|manage|panel|
             dashboard|config)(?:[\w\-/]*))?)["']""", re.X | re.I)

# Assignments that reveal flag values: "name": true, name=false.
_FLAG_VALUE_RE = re.compile(
    r"""["']?([\w][\w\-]{1,60})["']?\s*[:=]\s*(true|false)""")

_MAX_HITS = 50


def extract_feature_flags(js: str) -> List[Dict[str, Any]]:
    """Flag names (plus values when assigned nearby)."""
    text = js or ""
    found: Dict[str, Dict[str, Any]] = {}
    for rx in _FLAG_RES:
        for match in rx.finditer(text):
            name = match.group(1)
            if name.lower() in ("true", "false", "null", "return",
                                 "function", "const", "var", "let"):
                continue
            found.setdefault(name, {"name": name, "value": None})
            if len(found) >= _MAX_HITS:
                break
    for match in _FLAG_VALUE_RE.finditer(text):
        name = match.group(1)
        if name in found:
            found[name]["value"] = match.group(2) == "true"
    return sorted(found.values(), key=lambda d: d["name"])


def extract_admin_routes(js: str) -> List[Dict[str, Any]]:
    """Absolute-path strings with privileged segments (unverified)."""
    out: Dict[str, Dict[str, Any]] = {}
    for match in _ADMIN_PATH_RE.finditer(js or ""):
        path = "/" + match.group(1).lstrip("/")
        if len(path) > 200:
            continue
        out.setdefault(path, {"path": path})
        if len(out) >= _MAX_HITS:
            break
    return sorted(out.values(), key=lambda d: d["path"])


def detect_flag_sdks(js: str) -> List[str]:
    """Vendor SDK markers present in the bundle."""
    text = js or ""
    return sorted(name for name, rx in _SDK_RES if rx.search(text))


def analyze_bundle(js: str, source_url: str = "") -> Dict[str, Any]:
    """All three extractors over one bundle."""
    return {"source": source_url,
            "flags": extract_feature_flags(js),
            "admin_routes": extract_admin_routes(js),
            "sdks": detect_flag_sdks(js)}
