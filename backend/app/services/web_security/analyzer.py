"""
Web Security Intelligence Analyzer for OpenRecon 3.0.
Evaluates HTTP Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy), Cookie flags (Secure, HttpOnly, SameSite), TLS/Certificate posture,
and technology fingerprinting with reasoned severity.
"""

from typing import Any, Dict, List
from urllib.parse import urlparse

from app.core.security_guard import SecurityGovernanceGuard
from app.core.tls_config import probe_tls_certificate


class WebSecurityAnalyzer:
    """Evaluates web security posture from headers, cookies, and TLS telemetry."""

    @staticmethod
    def analyze_headers(headers: Dict[str, str], is_https: bool = True) -> List[Dict[str, Any]]:
        low = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        findings: List[Dict[str, Any]] = []

        if is_https and "strict-transport-security" not in low:
            findings.append({
                "control": "HSTS",
                "severity": "MEDIUM",
                "evidence": "Missing Strict-Transport-Security header on HTTPS endpoint.",
                "reason": "Without HSTS, clients may be downgraded to plaintext HTTP on initial navigation.",
            })

        if "content-security-policy" not in low:
            findings.append({
                "control": "CSP",
                "severity": "MEDIUM",
                "evidence": "Missing Content-Security-Policy header.",
                "reason": "Absence of CSP increases blast radius of XSS and unauthorized script execution.",
            })
        elif "unsafe-inline" in low["content-security-policy"] or "unsafe-eval" in low["content-security-policy"]:
            findings.append({
                "control": "CSP",
                "severity": "LOW",
                "evidence": f"Permissive CSP directives detected: {low['content-security-policy'][:160]}",
                "reason": "unsafe-inline / unsafe-eval weakens XSS mitigation.",
            })

        if "x-frame-options" not in low and "frame-ancestors" not in low.get("content-security-policy", "").lower():
            findings.append({
                "control": "X-Frame-Options",
                "severity": "LOW",
                "evidence": "Missing X-Frame-Options and CSP frame-ancestors.",
                "reason": "Endpoint may be embedded in an iframe (clickjacking risk).",
            })

        if low.get("x-content-type-options", "").lower() != "nosniff":
            findings.append({
                "control": "X-Content-Type-Options",
                "severity": "LOW",
                "evidence": "Missing or non-nosniff X-Content-Type-Options header.",
                "reason": "Browsers may MIME-sniff responses.",
            })

        if "referrer-policy" not in low:
            findings.append({
                "control": "Referrer-Policy",
                "severity": "INFO",
                "evidence": "Missing Referrer-Policy header.",
                "reason": "URL path/query parameters could leak via Referer header.",
            })

        return findings

    @staticmethod
    def analyze_cookies(set_cookie_headers: List[str], is_https: bool = True) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for raw in set_cookie_headers or []:
            cookie_name = raw.split("=", 1)[0].strip()
            low = raw.lower()
            missing_flags = []
            if is_https and "secure" not in low:
                missing_flags.append("Secure")
            if "httponly" not in low:
                missing_flags.append("HttpOnly")
            if "samesite" not in low:
                missing_flags.append("SameSite")
            if missing_flags:
                findings.append({
                    "control": "CookieSecurity",
                    "cookie": cookie_name,
                    "severity": "MEDIUM" if "Secure" in missing_flags or "HttpOnly" in missing_flags else "LOW",
                    "evidence": f"Cookie '{cookie_name}' missing flags: {', '.join(missing_flags)}",
                    "reason": "Missing cookie attributes expose session identifiers to interception, XSS, or CSRF.",
                })
        return findings

    @classmethod
    def inspect_url_posture(cls, url: str, headers: Dict[str, str], set_cookies: List[str]) -> Dict[str, Any]:
        safety = SecurityGovernanceGuard.validate_target_safety(url, resolve_dns=True)
        if not safety.get("safe"):
            raise ValueError(f"Blocked by RoE/Anti-SSRF: {safety.get('reason')}")

        parsed = urlparse(url)
        is_https = parsed.scheme.lower() == "https"
        tls_posture = probe_tls_certificate(parsed.hostname or "", parsed.port or 443) if is_https else None

        header_findings = cls.analyze_headers(headers, is_https=is_https)
        cookie_findings = cls.analyze_cookies(set_cookies, is_https=is_https)
        tls_findings: List[Dict[str, Any]] = []
        if tls_posture and not tls_posture.get("tls_valid"):
            tls_findings.append({
                "control": "TLS",
                "severity": "HIGH",
                "evidence": tls_posture.get("error") or "TLS certificate validation failed.",
                "reason": "Invalid, expired, or untrusted TLS certificate exposes traffic to MITM.",
            })

        return {
            "url": url,
            "tls_posture": tls_posture,
            "findings": tls_findings + header_findings + cookie_findings,
        }
