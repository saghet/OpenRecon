"""
Centralized TLS/SSL Configuration & Verification Guard for OpenRecon.
Enforces mandatory certificate validation, hostname verification,
trusted CA bundle management, and explicit handling of expired/invalid certs.
"""

import os
import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import certifi

from app.core.config import settings

logger = logging.getLogger(__name__)


def get_ca_bundle() -> str:
    """
    Returns the trusted CA bundle path:
    1. settings.CUSTOM_CA_BUNDLE (if configured and exists)
    2. SSL_CERT_FILE / REQUESTS_CA_BUNDLE env vars (if set and exist)
    3. certifi.where() fallback
    """
    candidates = [
        getattr(settings, "CUSTOM_CA_BUNDLE", None),
        os.environ.get("SSL_CERT_FILE"),
        os.environ.get("REQUESTS_CA_BUNDLE"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
        if path:
            logger.warning(f"Configured CA bundle path does not exist: {path}. Falling back to certifi.")
    return certifi.where()


def create_secure_ssl_context(ca_bundle: Optional[str] = None) -> ssl.SSLContext:
    """
    Creates a strict TLS 1.2+ SSLContext with mandatory certificate
    and hostname verification. Never disables verification.
    """
    cafile = ca_bundle if (ca_bundle and os.path.isfile(ca_bundle)) else get_ca_bundle()
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def get_httpx_verify(ca_bundle: Optional[str] = None) -> ssl.SSLContext:
    """
    Returns a strict SSLContext suitable for httpx.AsyncClient(verify=...)
    and httpx.AsyncHTTPTransport(verify=...).
    """
    return create_secure_ssl_context(ca_bundle=ca_bundle)


def probe_tls_certificate(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
    ca_bundle: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Inspects a target's TLS certificate using strict verification.
    Explicitly captures expired, untrusted, or hostname-mismatch errors
    without ever disabling certificate validation.
    """
    result: Dict[str, Any] = {
        "tls_valid": False,
        "hostname_verified": False,
        "expired": False,
        "issuer": None,
        "subject": None,
        "not_after": None,
        "tls_version": None,
        "error": None,
    }
    ctx = create_secure_ssl_context(ca_bundle=ca_bundle)
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert() or {}
                result["tls_valid"] = True
                result["hostname_verified"] = True
                result["tls_version"] = ssock.version()
                issuer_tuples = cert.get("issuer", ())
                issuer_dict = dict(x[0] for x in issuer_tuples if x)
                result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
                subject_tuples = cert.get("subject", ())
                subject_dict = dict(x[0] for x in subject_tuples if x)
                result["subject"] = subject_dict.get("commonName")
                not_after_str = cert.get("notAfter")
                result["not_after"] = not_after_str
                if not_after_str:
                    try:
                        exp_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        result["expired"] = exp_dt < datetime.now(timezone.utc)
                    except ValueError:
                        pass
    except ssl.SSLCertVerificationError as e:
        msg = str(e)
        result["error"] = f"TLS certificate verification failed: {msg}"
        result["expired"] = "expired" in msg.lower()
    except ssl.SSLError as e:
        result["error"] = f"TLS handshake error: {e}"
    except OSError as e:
        result["error"] = f"TLS connection error: {e}"

    return result
