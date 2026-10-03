"""Structured URL normalization."""
from urllib.parse import (urlsplit, urlunsplit, parse_qsl, urlencode,
                          unquote, quote)
from typing import List, Tuple


def normalize_url(url: str) -> str:
    if not url:
        return url
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    if not host:
        return url
    port = parts.port
    netloc = host
    if port and not ((scheme == "http" and port == 80) or
                     (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    path = unquote(path)
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    path = quote(path, safe="/@:!$&'()*+,;=-._~")
    q = parse_qsl(parts.query, keep_blank_values=True)
    q.sort(key=lambda kv: (kv[0], kv[1]))
    query = urlencode(q, doseq=True)
    return urlunsplit((scheme, netloc, path, query, ""))


def extract_query_params(url: str) -> List[Tuple[str, str]]:
    return parse_qsl(urlsplit(url).query, keep_blank_values=True)
