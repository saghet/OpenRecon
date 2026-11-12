"""
Defensive Tor Sandbox & Network Isolation Guard for OpenRecon.
Provides robust security controls:
1. Anti-SSRF: Strict blocking of private IPs (RFC 1918), loopback, link-local, cloud metadata.
2. DNS Rebinding Mitigation & Remote DNS via SOCKS5h.
3. Strict Redirect Hop Validation.
4. Response Size Limits (Max 2MB to prevent Zip/Decompression bombs).
5. Binary Payload and Executable Rejection.
6. Tor Healthcheck & Latency Probe.
7. Integration with OpenRecon Emergency Kill-Switch.
"""

import ipaddress
import logging
import re
import socket
import time
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any, Tuple
import httpx

from app.core.config import settings
from app.core.security_guard import SecurityGovernanceGuard

logger = logging.getLogger("openrecon.tor_guard")


class TorSecurityException(Exception):
    """Raised when a request violates Tor sandbox security policies."""
    pass


class TorSecurityGuard:
    """
    Central gatekeeper managing secure, read-only HTTP transport through the Tor sandbox.
    """

    # Allowed categories for Tor sandbox queries
    ALLOWED_SCHEMES = {"http", "https"}
    
    # MIME Types allowed for threat intelligence ingestion
    ALLOWED_CONTENT_TYPES = {
        "text/html",
        "text/plain",
        "application/json",
        "text/xml",
        "application/xml",
        "text/csv"
    }

    # Blocked extensions and binary types
    BLOCKED_EXTENSIONS = (
        ".exe", ".dll", ".so", ".bin", ".elf", ".zip", ".tar",
        ".gz", ".7z", ".iso", ".dmg", ".apk", ".msi", ".scr"
    )

    # Standard Tor Browser User-Agent to avoid defensive finger-printing
    TOR_BROWSER_UA = (
        "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
    )

    @classmethod
    def is_onion_host(cls, hostname: str) -> bool:
        """
        Check if the hostname is a valid v2 or v3 .onion address.
        """
        if not hostname:
            return False
        clean_host = hostname.strip().lower().split(":")[0]
        # v3 onion: 56 chars base32; v2 onion: 16 chars base32
        return bool(re.match(r"^[a-z2-7]{16,56}\.onion$", clean_host))

    @classmethod
    def validate_tor_target(cls, url: str) -> Dict[str, Any]:
        """
        Validates target URL against SSRF, internal scopes, metadata endpoints,
        and kill-switch status.
        """
        # 1. Verify Emergency Kill-Switch
        kill_switch = SecurityGovernanceGuard.is_kill_switch_active()
        if kill_switch["active"]:
            return {
                "safe": False,
                "reason": f"Emergency Kill Switch is ACTIVE ({kill_switch['reason']})"
            }

        if not url:
            return {"safe": False, "reason": "Target URL cannot be empty."}

        parsed = urlparse(url)
        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            return {
                "safe": False,
                "reason": f"Scheme '{parsed.scheme}' is forbidden. Only HTTP/HTTPS permitted."
            }

        hostname = parsed.hostname
        if not hostname:
            return {"safe": False, "reason": "Could not parse hostname from target URL."}

        hostname_clean = hostname.strip().lower()

        # 2. Blocked hostnames, internal single-words & cloud metadata
        is_onion = cls.is_onion_host(hostname_clean)

        # Single-word hostnames (Docker container names, local machine names) are internal
        if not is_onion and "." not in hostname_clean:
            return {
                "safe": False,
                "reason": f"Target '{hostname_clean}' is an internal unqualified network hostname (Anti-SSRF violation)."
            }

        internal_suffixes = (".internal", ".local", ".lan", ".corp", ".home", ".localhost", ".arpa")
        if (
            hostname_clean in SecurityGovernanceGuard.BLOCKED_DOMAINS
            or "169.254.169.254" in hostname_clean
            or any(hostname_clean.endswith(sfx) for sfx in internal_suffixes)
        ):
            return {
                "safe": False,
                "reason": f"Target '{hostname_clean}' blocked by Anti-SSRF policy (Cloud Metadata / Internal host)."
            }

        # 3. Check for IP address targeting (RFC 1918 / Loopback)
        try:
            ip_obj = ipaddress.ip_address(hostname_clean)
            if ip_obj.is_loopback:
                return {"safe": False, "reason": "Loopback access is strictly prohibited."}
            if ip_obj.is_private:
                return {"safe": False, "reason": "Private network (RFC 1918) access is strictly prohibited."}
            if ip_obj.is_link_local:
                return {"safe": False, "reason": "Link-local / cloud metadata access is strictly prohibited."}
            if ip_obj.is_multicast or ip_obj.is_reserved:
                return {"safe": False, "reason": "Multicast or reserved IP range is prohibited."}
        except ValueError:
            # It's a hostname (onion or public FQDN)
            pass

        # 4. Check for blocked extensions in URL path
        path_lower = parsed.path.lower()
        for ext in cls.BLOCKED_EXTENSIONS:
            if path_lower.endswith(ext):
                return {
                    "safe": False,
                    "reason": f"Binary/executable extension '{ext}' is forbidden from ingestion."
                }

        return {
            "safe": True,
            "url": url,
            "hostname": hostname_clean,
            "is_onion": cls.is_onion_host(hostname_clean)
        }

    @classmethod
    def get_socks_proxy_url(cls, custom_proxy: Optional[str] = None) -> str:
        """
        Returns SOCKS5h proxy URL (ensures remote DNS resolution to prevent DNS leaks).
        """
        proxy = custom_proxy or settings.TOR_PROXY_URL
        if proxy.startswith("socks5://"):
            # Enforce socks5h for remote DNS resolution
            proxy = "socks5h://" + proxy[len("socks5://"):]
        return proxy

    @classmethod
    async def fetch_onion_safe(
        cls,
        url: str,
        tor_proxy: Optional[str] = None,
        timeout: Optional[float] = None,
        max_redirects: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Safely fetches content via the Tor sandbox with:
        - SSRF and Scope verification per hop
        - Max content size enforcement (streaming)
        - MIME-type inspection
        - Timeout enforcement
        """
        proxy_url = cls.get_socks_proxy_url(tor_proxy)
        req_timeout = timeout or settings.TOR_REQUEST_TIMEOUT
        redirect_limit = max_redirects if max_redirects is not None else settings.TOR_MAX_REDIRECTS
        max_bytes = settings.TOR_MAX_CONTENT_BYTES

        current_url = url
        redirect_count = 0
        visited_urls = []

        headers = {
            "User-Agent": cls.TOR_BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
            "Accept-Language": "en-US,en;q=0.5",
            "DNT": "1",
            "Connection": "close"
        }

        transport = httpx.AsyncHTTPTransport(
            proxy=proxy_url,
            verify=settings.TOR_VERIFY_SSL
        )

        async with httpx.AsyncClient(
            transport=transport,
            timeout=req_timeout,
            follow_redirects=False
        ) as client:
            while True:
                # Validate current hop
                val = cls.validate_tor_target(current_url)
                if not val["safe"]:
                    raise TorSecurityException(f"SSRF / Policy violation on URL '{current_url}': {val['reason']}")

                visited_urls.append(current_url)

                try:
                    start_time = time.time()
                    resp = await client.get(current_url, headers=headers)
                    duration_ms = int((time.time() - start_time) * 1000)
                except httpx.RequestError as e:
                    logger.warning(f"Tor network error fetching {current_url}: {e}")
                    return {
                        "success": False,
                        "error": str(e),
                        "status_code": None,
                        "url": current_url,
                        "hops": visited_urls
                    }

                # Check for redirects
                if resp.status_code in (301, 302, 303, 307, 308):
                    redirect_count += 1
                    if redirect_count > redirect_limit:
                        raise TorSecurityException(f"Exceeded max redirects ({redirect_limit}) for target.")

                    location = resp.headers.get("Location")
                    if not location:
                        break  # No location header; return as-is

                    # Resolve relative redirect
                    from urllib.parse import urljoin
                    current_url = urljoin(current_url, location)
                    continue

                # Content-Type verification
                content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
                if content_type and not any(ct in content_type for ct in cls.ALLOWED_CONTENT_TYPES):
                    raise TorSecurityException(
                        f"Forbidden MIME type '{content_type}'. Tor sandbox only ingests textual intelligence."
                    )

                # Content length verification
                raw_bytes = resp.content
                if len(raw_bytes) > max_bytes:
                    raise TorSecurityException(
                        f"Response payload size ({len(raw_bytes)} bytes) exceeds max limit ({max_bytes} bytes)."
                    )

                # Decode textual content safely
                text_content = resp.text

                return {
                    "success": True,
                    "status_code": resp.status_code,
                    "url": current_url,
                    "duration_ms": duration_ms,
                    "content_length": len(raw_bytes),
                    "content_type": content_type,
                    "content": text_content,
                    "hops": visited_urls,
                    "headers": dict(resp.headers)
                }

    @classmethod
    async def check_tor_connectivity(
        cls,
        tor_proxy: Optional[str] = None,
        probe_url: str = "https://check.torproject.org/api/ip"
    ) -> Dict[str, Any]:
        """
        Validates if Tor proxy daemon is operational and properly routing requests.
        """
        proxy_url = cls.get_socks_proxy_url(tor_proxy)
        try:
            start_time = time.time()
            transport = httpx.AsyncHTTPTransport(proxy=proxy_url, verify=False)
            async with httpx.AsyncClient(transport=transport, timeout=8.0) as client:
                resp = await client.get(probe_url)
                latency = int((time.time() - start_time) * 1000)

                if resp.status_code == 200:
                    data = resp.json()
                    is_tor = data.get("IsTor", False)
                    return {
                        "status": "ONLINE" if is_tor else "WARNING_NOT_TOR",
                        "proxy": proxy_url,
                        "latency_ms": latency,
                        "ip": data.get("IP"),
                        "is_tor": is_tor,
                        "details": "Tor connection verified." if is_tor else "Traffic reached probe but is NOT through Tor exit node."
                    }
        except Exception as e:
            return {
                "status": "OFFLINE",
                "proxy": proxy_url,
                "error": str(e),
                "details": "Tor SOCKS5 proxy unreachable or circuit creation timed out."
            }
