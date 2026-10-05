"""Burp Suite handoff (offline export, zero network).

Turns collected endpoints + leads into artifacts a human drops into
Burp and verifies by hand:

- ``burp/urls.txt`` — live in-scope URLs, one per line. Paste into
  Target > Scope (include rules), Content discovery, or Intruder.
- ``burp/requests/*.txt`` — raw HTTP requests, one file each. Paste a
  file straight into a Repeater tab (both editions accept pasted raw
  requests), then Send to Intruder / Comparer / Collaborator.
- ``burp/sitemap.xml`` — Burp site-map XML schema (same shape as
  Target > Save selected items) with base64 requests, for archiving
  and diffing runs. Items are marked unrequested: they were
  discovered, never fetched by us through Burp.
- ``burp/lead-checklist.md`` — per-lead Burp clicks: which tool,
  which payload positions, what to compare.

Request bodies reuse observed sample values when present, else empty
values — these are starting templates for manual testing, not probes.
Nothing here is sent anywhere; every byte stays in files.
"""
import base64
import html as _h
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import quote, urlparse

MAX_REQUEST_FILES = 500

_REPEATER_UA = "apex-fuzzer-lead"


def _slug(text: str, limit: int = 60) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-")
    return (slug[:limit] or "root").lower()


def _split_url(url: str) -> Tuple[str, str, int, str]:
    """(scheme, host, port, path_query) with explicit default ports."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or ""
    default = 443 if scheme == "https" else 80
    try:
        port = parsed.port or default
    except ValueError:
        port = default
    path = parsed.path or "/"
    target = path + (f"?{parsed.query}" if parsed.query else "")
    return scheme, host, port, target


def _param_pairs(params: Any) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for param in params or []:
        name = getattr(param, "name", "") or ""
        if not name or any(key == name for key, _ in pairs):
            continue
        sample = getattr(param, "sample_value", None)
        pairs.append((name, "" if sample is None else str(sample)))
    return pairs


def build_raw_request(endpoint: Any) -> str:
    """Minimal raw HTTP/1.1 request for an endpoint.

    GET keeps the query string. Non-GET methods with body parameters
    get a urlencoded body built from sample values (empty otherwise).
    Header parameters are echoed as headers; identity-like carriers
    are never invented — only names already on the endpoint appear.
    """
    method = (getattr(endpoint, "method", "") or "GET").upper()
    url = getattr(endpoint, "normalized_url", "") or \
        getattr(endpoint, "url", "")
    _, host, port, target = _split_url(url)
    lines = [f"{method} {target} HTTP/1.1",
             f"Host: {host}" + (f":{port}" if port not in (80, 443)
                                else ""),
             f"User-Agent: {_REPEATER_UA}",
             "Accept: */*",
             "Connection: close"]
    body = ""
    if method != "GET":
        pairs = _param_pairs(getattr(endpoint, "body_parameters", None))
        if pairs:
            body = "&".join(f"{quote(key, safe='')}="
                            f"{quote(value, safe='')}"
                            for key, value in pairs)
            lines.append("Content-Type: "
                         "application/x-www-form-urlencoded")
    for key, value in _param_pairs(
            getattr(endpoint, "header_parameters", None)):
        lowered = key.lower()
        if lowered in ("host", "content-length", "connection",
                       "cookie", "authorization"):
            continue
        lines.append(f"{key}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body.encode())}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def sitemap_xml(items: List[Tuple[Any, str]]) -> str:
    """Burp site-map XML for (endpoint, raw_request) pairs."""
    parts = ['<?xml version="1.0"?>\n<items>']
    for endpoint, raw in items:
        url = getattr(endpoint, "normalized_url", "") or \
            getattr(endpoint, "url", "")
        scheme, host, port, target = _split_url(url)
        parsed = urlparse(url)
        ext = ""
        last = (parsed.path or "").rsplit("/", 1)[-1]
        if "." in last:
            ext = last.rsplit(".", 1)[-1][:16]
        request = base64.b64encode(raw.encode()).decode()
        parts.append(
            "<item>"
            f"<url><![CDATA[{url}]]></url>"
            f"<host>{_h.escape(host)}</host>"
            f"<port>{port}</port>"
            f"<protocol>{_h.escape(scheme)}</protocol>"
            f"<method><![CDATA[{(getattr(endpoint, 'method', '') or 'GET').upper()}]]></method>"
            f"<path><![CDATA[{target}]]></path>"
            f"<extension>{_h.escape(ext)}</extension>"
            f"<request base64=\"true\"><![CDATA[{request}]]></request>"
            "<status>0</status><responselength>0</responselength>"
            "<mimetype></mimetype>"
            "<response base64=\"true\"><![CDATA[]]></response>"
            "<comment>apex-fuzzer lead: discovered, unrequested</comment>"
            "</item>")
    parts.append("</items>")
    return "\n".join(parts) + "\n"


# Lead kind -> Burp clicks a human follows to verify it.
BURP_STEPS = {
    "privileged-endpoint": (
        "Repeater: replay the request twice — once with a low-privilege "
        "session cookie, once with a high-privilege one (or anon vs "
        "authed). Send both responses to Comparer (word compare). "
        "Identical object served to both = test for BOLA/BFLA."),
    "id-param": (
        "Intruder (Sniper): mark the id parameter (§), load a harvested "
        "ID list (other users' objects), Start attack. Sort by length / "
        "grep-match ownership fields. A 200 serving another user's "
        "object = IDOR lead."),
    "url-param": (
        "Repeater + Collaborator client (Pro) or Interactsh: replace the "
        "URL value with your Collaborator/Interactsh hostname (unique "
        "per request), send, then Poll. A DNS/HTTP hit = blind-SSRF "
        "lead. Never point it at internal metadata addresses."),
    "redirect-sink": (
        "Repeater: swap the value to https://evil.example, then to "
        "javascript:alert(1) and //evil.example. A 30x Location echoing "
        "an external host = open-redirect lead."),
    "graphql-operation": (
        "Repeater: introspect (__schema), then replay the operation "
        "with another user's object ID in variables (Intruder Sniper "
        "over the variable). Same-shape object across users = "
        "GraphQL-BOLA lead."),
    "upload-surface": (
        "Repeater: replay the multipart body with a double-extension "
        "(shell.phtml/.svg), mismatched Content-Type, and oversized "
        "file. Fetch the stored URL back — execution/storage = lead."),
    "html-form": (
        "Repeater: submit a canary string (apexcanary + inert tag), "
        "then GET the render candidates and Search the response. "
        "Unescaped reflection in an active sink = stored-XSS lead."),
    "versioned-tech": (
        "Check the fingerprinted version against known CVEs (Scanner "
        "audit / Hackvertor / manual). Confirm on the live stack "
        "before reporting — banners lie."),
    "takeover-fingerprint": (
        "Manual: dig the CNAME, GET the host, compare against the "
        "provider's dangling-service page. Claim only with the token "
        "flow and program permission."),
    "param-rich": (
        "Intruder + Param Miner (Pro) or manual GET/POST/JSON/cookie "
        "guessing on this endpoint. New params loop back into the "
        "steps above."),
}


def lead_checklist(leads: List[Dict]) -> str:
    """Markdown: each lead with the Burp clicks that verify it."""
    lines = ["# Burp lead checklist",
             "",
             "> Generated from discovered-but-untested surface. Work top "
             "down; check off what you test. A lead is a pointer, not a "
             "finding — only what you reproduce by hand counts.",
             ""]
    for lead in leads:
        steps = BURP_STEPS.get(lead.get("kind", ""),
                               "Repeater: replay by hand and compare "
                               "against the baseline.")
        lines.append(f"## [{lead.get('priority', 'info')}] "
                     f"{lead.get('kind', 'lead')}")
        if lead.get("url"):
            lines.append(f"- where: `{lead['url']}`")
        if lead.get("param"):
            lines.append(f"- param: `{lead['param']}`")
        lines.append(f"- why: {lead.get('reason', '')}")
        lines.append(f"- in Burp: {steps}")
        lines.append("")
    return "\n".join(lines)


def export_burp(out_dir: Path, endpoints: List[Any],
                leads: List[Dict]) -> Dict[str, int]:
    """Write burp/ (urls, raw requests, sitemap XML, checklist)."""
    burp_dir = Path(out_dir) / "burp"
    requests_dir = burp_dir / "requests"
    requests_dir.mkdir(parents=True, exist_ok=True)
    seen_urls = set()
    items: List[Tuple[Any, str]] = []
    for endpoint in endpoints or []:
        url = getattr(endpoint, "normalized_url", "") or \
            getattr(endpoint, "url", "")
        if not url or not url.startswith("http"):
            continue
        key = (getattr(endpoint, "method", "GET").upper(), url)
        if key in seen_urls:
            continue
        seen_urls.add(key)
        if len(items) >= MAX_REQUEST_FILES:
            break
        items.append((endpoint, build_raw_request(endpoint)))
    for index, (endpoint, raw) in enumerate(items, 1):
        url = getattr(endpoint, "normalized_url", "") or \
            getattr(endpoint, "url", "")
        _, host, _, target = _split_url(url)
        method = (getattr(endpoint, "method", "") or "GET").upper()
        name = (f"{index:03d}-{method}-{_slug(host)}-"
                f"{_slug(target.split('?')[0])}.txt")
        (requests_dir / name).write_text(raw)
    urls = sorted({getattr(ep, "normalized_url", "") or
                   getattr(ep, "url", "")
                   for ep, _ in items})
    (burp_dir / "urls.txt").write_text("\n".join(urls) +
                                       ("\n" if urls else ""))
    (burp_dir / "sitemap.xml").write_text(sitemap_xml(items))
    (burp_dir / "lead-checklist.md").write_text(lead_checklist(leads))
    return {"requests": len(items), "urls": len(urls),
            "sitemap_items": len(items), "leads": len(leads)}
