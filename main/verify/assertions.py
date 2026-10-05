"""User-supplied JSONPath assertions (Terra M2.4).

Complex workflows are application-specific, so beyond the generic
verifiers the operator declares expected post-conditions:

```yaml
business:
  assertions:
    - endpoint: "/api/cart/items"
      parameter: "quantity"
      method: POST
      after_read: "/api/cart"
      checks:
        - jsonpath: "$.items[?(@.sku == 'SKU-1')].quantity"
          rule: "gte"
          value: 0
```

Supported JSONPath subset (deliberately small): dotted fields
(`$.a.b`), list indexes (`$.a[0].b`), and one equality filter
(`$.items[?(@.sku == 'SKU-1')].quantity`, string or number RHS).
Rules: `gte | lte | eq | ne | contains`. Anything outside the
subset is `inconclusive`, never a pass or fail.
"""
import json
import re
from typing import Any, Dict, List, Tuple

_FILTER_RE = re.compile(
    r"^\$\.(?P<base>[A-Za-z_][\w]*)\[\?\(@\.(?P<key>[A-Za-z_][\w]*)"
    r"\s*==\s*(?P<rhs>'[^']*'|\"[^\"]*\"|-?\d+(?:\.\d+)?)\)\]"
    r"(?P<rest>(?:\.[A-Za-z_][\w]*|\[\d+\])*)$")
_DOTTED_RE = re.compile(
    r"^\$(?P<rest>(?:\.[A-Za-z_][\w]*|\[\d+\])*)$")
_SEG_RE = re.compile(r"\.([A-Za-z_][\w]*)|\[(\d+)\]")


def _parse_rhs(raw: str) -> Any:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _walk_segments(data: Any, rest: str) -> List[Any]:
    current = [data]
    for m in _SEG_RE.finditer(rest):
        field, index = m.group(1), m.group(2)
        nxt: List[Any] = []
        for node in current:
            if field is not None and isinstance(node, dict) \
                    and field in node:
                nxt.append(node[field])
            elif index is not None and isinstance(node, list):
                i = int(index)
                if 0 <= i < len(node):
                    nxt.append(node[i])
        current = nxt
        if not current:
            break
    return current


def jsonpath_get(data: Any, expr: str) -> Tuple[bool, List[Any]]:
    """Evaluate the supported subset. Returns (understood, matches)."""
    if not isinstance(expr, str):
        return False, []
    m = _FILTER_RE.match(expr.strip())
    if m:
        if not isinstance(data, dict) or m.group("base") not in data:
            return True, []
        items = data[m.group("base")]
        if not isinstance(items, list):
            return True, []
        want = _parse_rhs(m.group("rhs"))
        out = []
        for item in items:
            if isinstance(item, dict) and item.get(m.group("key")) == want:
                out.extend(_walk_segments(item, m.group("rest")))
        return True, out
    m2 = _DOTTED_RE.match(expr.strip())
    if m2:
        return True, _walk_segments(data, m2.group("rest"))
    return False, []


def check_rule(actual: Any, rule: str, expected: Any) -> bool:
    try:
        if rule == "eq":
            return actual == expected
        if rule == "ne":
            return actual != expected
        if rule == "gte":
            return float(actual) >= float(expected)
        if rule == "lte":
            return float(actual) <= float(expected)
        if rule == "contains":
            return str(expected) in str(actual)
    except (TypeError, ValueError):
        return False
    return False


def evaluate_assertions(assertions: List[Dict[str, Any]],
                        body_text: str) -> Tuple[str, str, Dict[str, Any]]:
    """Run assertion checks against a readback body.

    Returns (passed_all, detail, evidence). A failed check means the
    invariant held (good for the target); a passed check on an abuse
    value means the violation persisted. Malformed config or bodies
    yield inconclusive.
    """
    try:
        data = json.loads(body_text or "")
    except (ValueError, TypeError):
        return "inconclusive", "readback body is not JSON", {}
    results = []
    for check in assertions or []:
        expr = check.get("jsonpath", "")
        rule = check.get("rule", "")
        expected = check.get("value")
        understood, matches = jsonpath_get(data, expr)
        if not understood:
            return "inconclusive", \
                f"unsupported jsonpath (not evaluated): {expr}", {}
        if rule not in ("gte", "lte", "eq", "ne", "contains"):
            return "inconclusive", f"unknown rule: {rule}", {}
        ok = any(check_rule(m, rule, expected) for m in matches)
        results.append({"jsonpath": expr, "rule": rule,
                        "value": expected,
                        "matched_values": matches[:5],
                        "holds": ok})
    if not results:
        return "inconclusive", "no checks defined", {}
    bad = [r for r in results if not r["holds"]]
    if bad:
        return "failed", \
            f"{len(bad)}/{len(results)} checks failed " \
            f"(first: {bad[0]['jsonpath']})", {"checks": results}
    return "passed", f"all {len(results)} checks hold", \
        {"checks": results}


def matching_assertions(assertions: List[Dict[str, Any]],
                        endpoint_path: str, parameter: str,
                        method: str) -> List[Dict[str, Any]]:
    """Assertions whose endpoint/parameter/method select this probe."""
    out = []
    for a in assertions or []:
        if not isinstance(a, dict):
            continue
        ep = str(a.get("endpoint", ""))
        if ep and ep not in (endpoint_path,):
            # match on path suffix as well (/api/cart/items)
            if endpoint_path != ep and not endpoint_path.endswith(ep):
                continue
        if a.get("parameter") and a.get("parameter") != parameter:
            continue
        if a.get("method") and \
                str(a.get("method")).upper() != method.upper():
            continue
        out.append(a)
    return out
