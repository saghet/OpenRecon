"""
URL Normalization, Deduplication & GF-Compatible Parameter Classification
for OpenRecon 3.0 WebCopilotAdapter.
Replaces unsafe bash/sed/uro/urldedupe pipelines with deterministic Python logic.
"""

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

STATIC_EXTENSIONS: Set[str] = {
    ".css", ".jpg", ".jpeg", ".gif", ".png", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".tif", ".tiff",
    ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz", ".tar",
}

# Built-in GF-compatible parameter heuristics (inspired by Gf-Patterns)
GF_PARAM_PATTERNS: Dict[str, Set[str]] = {
    "xss": {
        "q", "s", "search", "query", "keyword", "keywords", "term", "name",
        "title", "msg", "message", "err", "error", "callback", "jsonp",
        "html", "text", "body", "comment", "email", "user", "username",
        "lang", "locale", "label", "value", "input", "data",
    },
    "sqli": {
        "id", "uid", "pid", "cid", "oid", "user_id", "item_id", "cat", "cat_id",
        "category", "page", "p", "limit", "offset", "order", "sort", "by",
        "dir", "filter", "where", "select", "table", "col", "column", "row",
        "report", "role", "type", "year", "month", "day", "start", "end",
    },
    "ssrf": {
        "url", "uri", "link", "src", "source", "dest", "destination", "target",
        "feed", "host", "domain", "proxy", "fetch", "webhook", "callback_url",
        "endpoint", "site", "html_url", "image_url", "avatar_url", "load",
    },
    "lfi": {
        "file", "filename", "filepath", "path", "doc", "document", "folder",
        "root", "pg", "style", "template", "tpl", "include", "inc", "dir",
        "download", "read", "view", "content", "layout", "mod", "module",
    },
    "rce": {
        "cmd", "exec", "command", "execute", "ping", "query", "jump", "code",
        "reg", "do", "func", "arg", "option", "load", "process", "step",
        "read", "function", "req", "feature", "exe", "module", "payload", "run",
    },
    "redirect": {
        "next", "url", "target", "rurl", "dest", "destination", "redir",
        "redirect", "redirect_uri", "redirect_url", "return", "return_url",
        "returnto", "return_to", "checkout_url", "continue", "view", "go", "out",
    },
    "crlf": {
        "redirect", "url", "next", "lang", "header", "location", "return",
        "view", "page", "referer", "ref",
    },
}

_SAFE_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*(?::\d{1,5})?$")


@dataclass
class NormalizedURL:
    url: str
    url_hash: str
    canonical_key: str
    scheme: str
    host: str
    hostname: str
    path: str
    query_params: List[str]
    has_params: bool
    gf_categories: List[str]


def is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 255:
        return False
    return bool(_SAFE_HOST_RE.match(host.strip().lower()))


def classify_gf_categories(path: str, param_names: List[str]) -> List[str]:
    categories: Set[str] = set()
    lower_params = {p.strip().lower() for p in param_names if p}
    for cat, keywords in GF_PARAM_PATTERNS.items():
        if lower_params & keywords:
            categories.add(cat)
    # Path hints for LFI/redirect
    lower_path = path.lower()
    if any(tok in lower_path for tok in ("download", "export", "readfile", "include")):
        categories.add("lfi")
    if any(tok in lower_path for tok in ("redirect", "logout", "login", "oauth")):
        if "redirect" in lower_params or "next" in lower_params or "return_to" in lower_params:
            categories.add("redirect")
    return sorted(categories)


def normalize_url(raw_url: str, drop_static: bool = True) -> Optional[NormalizedURL]:
    if not raw_url or not isinstance(raw_url, str):
        return None
    candidate = raw_url.strip()
    if not candidate or len(candidate) > 4096:
        return None
    if any(ch in candidate for ch in ("\x00", "\r", "\n", " ", "`", ";", "|", "$(")):
        return None

    try:
        parsed = urlparse(candidate)
    except Exception:
        return None

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None

    netloc = (parsed.netloc or "").strip().lower()
    if not netloc or "@" in netloc:
        return None

    hostname = (parsed.hostname or "").lower()
    if not hostname or not is_valid_hostname(netloc):
        return None

    # Strip default ports
    if (scheme == "http" and netloc.endswith(":80")) or (scheme == "https" and netloc.endswith(":443")):
        netloc = netloc.rsplit(":", 1)[0]

    path = parsed.path or "/"
    if drop_static:
        lower_path = path.lower()
        if any(lower_path.endswith(ext) for ext in STATIC_EXTENSIONS):
            return None

    # Parse and sort query parameters deterministically
    qs = parse_qs(parsed.query, keep_blank_values=True)
    sorted_params = sorted(qs.keys())
    normalized_query = urlencode(
        [(k, qs[k][0] if qs[k] else "") for k in sorted_params],
        doseq=False,
    )

    clean_url = urlunparse((scheme, netloc, path, "", normalized_query, ""))
    url_hash = hashlib.sha256(clean_url.encode("utf-8")).hexdigest()

    # Canonical key ignores parameter values so /search?q=a and /search?q=b deduplicate
    param_sig = ",".join(sorted_params)
    canonical_raw = f"{scheme}|{netloc}|{path}|{param_sig}"
    canonical_key = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()

    gf_cats = classify_gf_categories(path, sorted_params)

    return NormalizedURL(
        url=clean_url,
        url_hash=url_hash,
        canonical_key=canonical_key,
        scheme=scheme,
        host=netloc,
        hostname=hostname,
        path=path,
        query_params=sorted_params,
        has_params=bool(sorted_params),
        gf_categories=gf_cats,
    )


def deduplicate_urls(
    raw_urls: List[Tuple[str, str]],
    drop_static: bool = True,
    max_urls: int = 2000,
) -> Dict[str, Dict]:
    """
    Normalizes and deduplicates (raw_url, source) tuples by canonical_key.
    Preserves all discovery sources for each canonical endpoint.
    """
    deduped: Dict[str, Dict] = {}
    for raw_url, source in raw_urls:
        norm = normalize_url(raw_url, drop_static=drop_static)
        if not norm:
            continue
        if norm.canonical_key not in deduped:
            deduped[norm.canonical_key] = {
                "normalized": norm,
                "sources": [source],
            }
            if len(deduped) >= max_urls:
                break
        else:
            existing_sources = deduped[norm.canonical_key]["sources"]
            if source not in existing_sources:
                existing_sources.append(source)
    return deduped
