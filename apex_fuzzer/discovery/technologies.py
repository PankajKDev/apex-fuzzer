"""Technology fingerprinting.

Each detection carries a ``category`` that gates which test families run
downstream (spec §7):

- ``waf``      → WAF bypass / mutation engine selection
- ``gateway``  → API-gateway-specific bypass patterns
- ``auth``     → provider-specific auth tests (Auth0/Okta/Cognito/Firebase)
- ``cloud``    → cloud metadata-endpoint SSRF payloads (AWS 169.254.169.254, ...)
- ``frontend`` → SPA framework signals (route/param discovery heuristics)
- ``server``   → back-end server / app framework
"""
import re
from typing import List, Dict, Optional
from ..models import Technology

_HEADER_RULES = [
    # (name, header, pattern, confidence, category)
    ("nginx", "server", r"nginx(?:/(\S+))?", "confirmed", "server"),
    ("Apache", "server", r"apache(?:/(\S+))?", "confirmed", "server"),
    ("IIS", "server", r"microsoft-iis(?:/(\S+))?", "confirmed", "server"),
    ("Express", "x-powered-by", r"express", "confirmed", "server"),
    ("PHP", "x-powered-by", r"php(?:/(\S+))?", "confirmed", "server"),
    ("ASP.NET", "x-powered-by", r"asp\.net", "confirmed", "server"),
    ("Next.js", "x-powered-by", r"next\.js", "confirmed", "frontend"),
    # API gateways (known bypass patterns: cached headers, key-logging)
    ("Kong", "server", r"\bkong\b", "probable", "gateway"),
    ("Apigee", "server", r"apigee", "probable", "gateway"),
    # Cloud providers
    ("Amazon S3", "server", r"amazons3", "confirmed", "cloud"),
    ("AWS ELB", "server", r"awselb", "probable", "cloud"),
    ("CloudFront", "via", r"cloudfront", "probable", "cloud"),
    ("Google Frontend", "server", r"google frontend", "confirmed", "cloud"),
    ("Azure", "server", r"\bazure\b|windowsazure", "probable", "cloud"),
    ("Vercel", "server", r"vercel", "confirmed", "cloud"),
    ("Netlify", "server", r"netlify", "probable", "cloud"),
]

_WAF_RULES = [
    # (name, header, pattern, evidence_note)
    ("Cloudflare", "server", r"cloudflare"),
    ("Cloudflare", "cf-ray", r"."),
    ("Sucuri", "x-sucuri-id", r"."),
    ("Akamai", "server", r"akamai"),
    ("Akamai", "x-akamai-.*", r"."),
    ("F5 BIG-IP", "server", r"big-?ip"),
    ("F5 BIG-IP", "set-cookie", r"bigipserverid|bigip"),
    ("Imperva", "server", r"imperva"),
    ("Imperva", "set-cookie", r"imperva"),
    ("Wallarm", "x-wallarm-request-id", r"."),
    ("ModSecurity", "server", r"modsecurity"),
    ("AWS WAF", "x-amzn-waf-evaluation", r"."),
]

_HTML_RULES = [
    # (name, pattern, confidence, category)
    ("WordPress",
     re.compile(r"<meta[^>]+name=['\"]generator['\"][^>]+content=['\"]WordPress", re.I),
     "confirmed", "server"),
    ("React", re.compile(r"data-reactroot|__REACT_DEVTOOLS", re.I),
     "probable", "frontend"),
    ("Next.js", re.compile(r"/_next/static/", re.I), "probable", "frontend"),
    ("Vue.js", re.compile(r"data-v-[0-9a-f]{8}|__vue__", re.I), "possible",
     "frontend"),
    ("Angular", re.compile(r"ng-version=|ng-app=", re.I), "probable",
     "frontend"),
    ("jQuery", re.compile(r"jquery(?:\.min)?\.js", re.I), "probable",
     "frontend"),
    ("Bootstrap",
     re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.I),
     "probable", "frontend"),
    ("Google Analytics",
     re.compile(r"google-analytics\.com|gtag\(", re.I), "probable", "other"),
    # API gateways via error pages
    ("AWS API Gateway",
     re.compile(r"api gateway|invalid api (?:action|key|usage)|"
                r"\"message\"\s*:\s*\".*api (?:is not authorized|key is invalid)", re.I),
     "probable", "gateway"),
    ("Apigee", re.compile(r"\bapigee\b", re.I), "probable", "gateway"),
    ("Kong", re.compile(r"\bkong\b.{0,40}(?:api|gateway)", re.I), "possible",
     "gateway"),
    # Cloud error pages
    ("Amazon S3", re.compile(
        r"Amazon S3 (?:service|error)|<Code>NoSuchKey</Code>|"
        r"The specified key does not exist", re.I), "confirmed", "cloud"),
    ("GCS", re.compile(
        r"storage\.googleapis\.com|<Code>AccessDenied</Code>", re.I),
     "probable", "cloud"),
    ("Azure", re.compile(
        r"WindowsAzure|Azure (?:Blob|Service Bus|Storage)|"
        r"InvalidQueryParameterValue", re.I), "probable", "cloud"),
    ("AWS metadata hint",
     re.compile(r"169\.254\.169\.254", re.I), "possible", "cloud"),
]

_COOKIE_RULES = [
    ("WordPress", re.compile(r"wordpress_", re.I), "probable", "server"),
    ("Django", re.compile(r"csrftoken|sessionid", re.I), "probable", "server"),
    ("Laravel", re.compile(r"laravel_session", re.I), "probable", "server"),
    ("Rails", re.compile(r"_rails_session", re.I), "probable", "server"),
    ("PHP", re.compile(r"PHPSESSID", re.I), "confirmed", "server"),
    ("ASP.NET", re.compile(r"ASP\.NET_SessionId", re.I), "confirmed",
     "server"),
    ("Cloudflare", re.compile(r"__cfduid|__cf_bm", re.I), "confirmed", "waf"),
    # Auth providers
    ("Auth0", re.compile(r"auth0\.(?:com|com\.au)|did_js", re.I), "probable",
     "auth"),
    ("Okta", re.compile(r"okta\b", re.I), "probable", "auth"),
]

# JS bundle content detection (spec §7) — minified bundles reveal frameworks
_JS_BUNDLE_RULES = [
    # (name, compiled pattern, confidence, category)
    ("React",
     re.compile(r"__react|react-dom|createRoot\(|__REACT_DEVTOOLS"),
     "probable", "frontend"),
    ("Vue.js",
     re.compile(r"__vue__|createApp\(|vue\.runtime"),
     "probable", "frontend"),
    ("Angular",
     re.compile(r"ngDoBootstrap|@angular/|zone\.js|__ngContext__"),
     "probable", "frontend"),
    ("Svelte",
     re.compile(r"__svelte|svelte_internal|\$\.tick\("),
     "possible", "frontend"),
    ("Next.js",
     re.compile(r"__NEXT_DATA__|/_next/static"),
     "probable", "frontend"),
    ("Nuxt",
     re.compile(r"__NUXT__|nuxt/app"),
     "probable", "frontend"),
    ("Redux",
     re.compile(r"__REDUX_DEVTOOLS|combineReducers"),
     "possible", "frontend"),
    ("Auth0 JS",
     re.compile(r"auth0\.sp[a-z]*\.(?:com|com\.au)|createAuth0Client"),
     "probable", "auth"),
    ("Okta JS",
     re.compile(r"okta-signin-widget|useroauth\.okta|OKTA_URL"),
     "probable", "auth"),
    ("Cognito",
     re.compile(r"cognito-identity|amazoncognitoidentity|cognito-idp\."),
     "probable", "auth"),
    ("Firebase Auth",
     re.compile(r"firebaseAuth|__firebase_auth|firebase\.com/auth"),
     "probable", "auth"),
    ("AWS SDK",
     re.compile(r"aws-amazon|amazonaws\.com"),
     "probable", "cloud"),
]


def _add(found: Dict[str, Technology], name: str,
         version: Optional[str], conf: str, evidence: str,
         category: str = "other"):
    cur = found.get(name)
    if cur is None:
        found[name] = Technology(name=name, version=version,
                                 confidence=conf, evidence=[evidence],
                                 category=category)
        return
    order = {"possible": 0, "probable": 1, "confirmed": 2}
    if order.get(conf, 0) > order.get(cur.confidence, 0):
        cur.confidence = conf
    if evidence not in cur.evidence:
        cur.evidence.append(evidence)
    if version and not cur.version:
        cur.version = version
    if cur.category == "other" and category != "other":
        cur.category = category


def detect(headers: Dict[str, str], html: str = "",
           set_cookies: List[str] | None = None) -> List[Technology]:
    found: Dict[str, Technology] = {}
    lh = {k.lower(): v for k, v in (headers or {}).items()}

    for name, hdr, pattern, conf, category in _HEADER_RULES:
        v = lh.get(hdr, "")
        if not v:
            continue
        m = re.search(pattern, v, re.I)
        if m:
            ver = m.group(1) if m.lastindex else None
            _add(found, name, ver, conf, f"header:{hdr}={v[:60]}",
                 category)

    for name, hdr, pattern in _WAF_RULES:
        if hdr.startswith("x-akamai"):  # any x-akamai-* header
            for k, v in lh.items():
                if k.startswith("x-akamai"):
                    _add(found, "Akamai", None, "confirmed",
                         f"header:{k}={v[:40]}", "waf")
                    break
        else:
            v = lh.get(hdr, "")
            if v and re.search(pattern, v, re.I):
                _add(found, name, None, "confirmed",
                     f"header:{hdr}={v[:40]}", "waf")

    body = html or ""
    for name, pat, conf, category in _HTML_RULES:
        m = pat.search(body)
        if m:
            _add(found, name, None, conf, f"html:{m.group(0)[:40]}",
                 category)

    for cookie in set_cookies or []:
        for name, pat, conf, category in _COOKIE_RULES:
            if pat.search(cookie):
                _add(found, name, None, conf,
                     f"cookie:{cookie.split('=')[0]}", category)
                break
    return list(found.values())


def detect_js_bundle(js_text: str) -> List[Technology]:
    """Detect SPA frameworks / auth SDKs / cloud SDKs from bundle contents.

    Spec §7: bundle contents are the most reliable signal for what the
    front-end is actually built with, and which auth SDK it ships.
    """
    if not js_text:
        return []
    found: Dict[str, Technology] = {}
    # cap the scan — bundles are huge, the markers live anywhere
    sample = js_text[:1_500_000]
    for name, pat, conf, category in _JS_BUNDLE_RULES:
        m = pat.search(sample)
        if m:
            _add(found, name, None, conf, f"js:{m.group(0)[:40]}", category)
    return list(found.values())


def detect_waf(headers: Dict[str, str]) -> Optional[str]:
    """Return the WAF name if one is fingerprinted, else None."""
    found: Dict[str, Technology] = {}
    for name, hdr, pattern in _WAF_RULES:
        if hdr.startswith("x-akamai"):
            continue
        v = (headers or {}).get(hdr, "")
        if v and re.search(pattern, v, re.I):
            found[name] = True
    for k, v in (headers or {}).items():
        if k.lower().startswith("x-akamai"):
            found["Akamai"] = True
    for name in found:
        if name == "Cloudflare":
            return "cloudflare"
        if name == "AWS WAF":
            return "aws"
        return name.lower()
    return None


def categories(techs: List[Technology]) -> Dict[str, List[str]]:
    """Group technology names by category for test gating."""
    out: Dict[str, List[str]] = {}
    for t in techs:
        cat = getattr(t, "category", "other") or "other"
        out.setdefault(cat, []).append(t.name)
    return out


def gate(techs: List[Technology], category: str, name: str) -> bool:
    """True if ``name`` was detected within ``category``."""
    return name in categories(techs).get(category, [])
