"""Endpoint classification."""
import re
from urllib.parse import urlparse
from ..models import EndpointType

_RULES = [
    (EndpointType.GRAPHQL, [r"/graphql", r"/gql\b"]),
    (EndpointType.ADMIN, [r"/admin", r"/manage", r"/dashboard", r"/console"]),
    (EndpointType.AUTH, [r"/login", r"/signin", r"/auth", r"/oauth",
                         r"/token", r"/register", r"/signup"]),
    (EndpointType.UPLOAD, [r"/upload", r"/attach", r"/file/upload"]),
    (EndpointType.DOWNLOAD, [r"/download", r"/export/file"]),
    (EndpointType.EXPORT, [r"/export"]),
    (EndpointType.IMPORT, [r"/import"]),
    (EndpointType.REDIRECT, [r"/redirect", r"/r\?", r"/out", r"/go"]),
    (EndpointType.WEBHOOK, [r"/webhook", r"/hooks?/"]),
    (EndpointType.CALLBACK, [r"/callback", r"/oauth2/callback"]),
    (EndpointType.PROXY, [r"/proxy", r"/fetch\?", r"/api/fetch"]),
    (EndpointType.API, [r"^/api/", r"^/v\d+/", r"^/rest/"]),
    (EndpointType.STATIC, [r"\.(css|js|png|jpe?g|gif|svg|woff2?|ico)$"]),
]


def classify(path: str) -> str:
    p = urlparse(path).path.lower() or "/"
    for etype, patterns in _RULES:
        for pat in patterns:
            if re.search(pat, p):
                return etype.value
    return EndpointType.PAGE.value
