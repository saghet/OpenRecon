"""
Controles de Seguridad para Domain Intelligence:
- Validación estricta de indicadores (Dominio, Subdominio, IPv4, IPv6, URL)
- Protección SSRF y Anti-DNS Rebinding (validación previa y post-resolución de IPs)
- Control de redirecciones hacia redes internas
- Cifrado simétrico (Fernet) de API Keys en base de datos
"""

import base64
import hashlib
import ipaddress
import re
import socket
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

import tldextract
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings
from app.core.security_guard import SecurityGovernanceGuard
from app.models.domain_intel import IndicatorInputType

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f\s]")
_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost", ".lan", ".home", ".corp", ".arpa")
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


class DomainSecurityError(ValueError):
    """Error lanzado cuando un indicador viola las políticas de seguridad o formato."""


def check_ip_is_public(ip_str: str) -> Tuple[bool, Optional[str]]:
    """Verifica que una IP sea estrictamente pública y enrutable en Internet."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, "Dirección IP inválida."

    if ip_obj.is_unspecified:
        return False, "Dirección IP no especificada (0.0.0.0 / ::) prohibida."
    if ip_obj.is_loopback:
        return False, "Dirección loopback (127.0.0.0/8 / ::1) prohibida por política SSRF."
    if ip_obj.is_private:
        return False, "Dirección de red privada (RFC 1918 / ULA) prohibida por política SSRF."
    if ip_obj.is_link_local:
        return False, "Dirección link-local / cloud metadata (169.254.0.0/16) prohibida."
    if ip_obj.is_multicast:
        return False, "Dirección multicast prohibida."
    if ip_obj.is_reserved:
        return False, "Dirección reservada prohibida."
    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in _CGNAT_NET:
        return False, "Rango CGNAT (100.64.0.0/10) prohibido por política SSRF."

    return True, None


def validate_hostname_syntax(hostname: str) -> str:
    """Valida sintaxis RFC 1035/1123 de un dominio o subdominio sin permitir inyección."""
    clean = hostname.strip().lower().rstrip(".")
    if not clean or len(clean) > 253:
        raise DomainSecurityError("Longitud de dominio inválida (debe estar entre 1 y 253 caracteres).")
    if _CONTROL_CHARS_RE.search(clean) or ".." in clean or "/" in clean or "\\" in clean or "@" in clean:
        raise DomainSecurityError("Caracteres no permitidos en el dominio (posible inyección o path traversal).")

    if clean in SecurityGovernanceGuard.BLOCKED_DOMAINS or any(clean.endswith(s) for s in _BLOCKED_SUFFIXES):
        raise DomainSecurityError(f"Dominio interno o reservado bloqueado por política anti-SSRF: {clean}")

    labels = clean.split(".")
    if len(labels) < 2:
        raise DomainSecurityError("El dominio debe incluir al menos un TLD válido (ej. ejemplo.com).")

    for label in labels:
        if not _DOMAIN_LABEL_RE.match(label):
            raise DomainSecurityError(f"Etiqueta DNS inválida en el dominio: '{label}'.")

    return clean


def validate_and_normalize_indicator(raw_input: str) -> Dict[str, Any]:
    """
    Identifica y valida el tipo de indicador (DOMAIN, SUBDOMAIN, IPV4, IPV6, URL).
    Rechaza entradas malformadas, credenciales embebidas o destinos internos.
    """
    if not raw_input or not isinstance(raw_input, str):
        raise DomainSecurityError("El indicador no puede estar vacío.")

    candidate = raw_input.strip()
    if len(candidate) > 1024:
        raise DomainSecurityError("El indicador excede la longitud máxima permitida (1024).")
    if _CONTROL_CHARS_RE.search(candidate):
        raise DomainSecurityError("El indicador contiene caracteres de control o espacios no permitidos.")
    if ".." in candidate and not candidate.startswith("["):
        # Prevenir path traversal en rutas/URLs
        if "../" in candidate or "..\\" in candidate:
            raise DomainSecurityError("Patrón de path traversal detectado en el indicador.")

    # 1. Verificar si es IPv4 o IPv6 directa
    try:
        ip_obj = ipaddress.ip_address(candidate)
        is_pub, reason = check_ip_is_public(str(ip_obj))
        if not is_pub:
            raise DomainSecurityError(reason or "IP bloqueada por política SSRF.")
        input_type = IndicatorInputType.IPV4 if isinstance(ip_obj, ipaddress.IPv4Address) else IndicatorInputType.IPV6
        return {
            "raw_input": candidate,
            "normalized_target": str(ip_obj),
            "normalized_domain": str(ip_obj),
            "input_type": input_type,
        }
    except ValueError:
        pass

    # 2. Verificar si es URL completa
    if "://" in candidate:
        parsed = urlparse(candidate)
        if parsed.scheme not in ("http", "https"):
            raise DomainSecurityError(f"Esquema de URL no permitido: '{parsed.scheme}'. Solo http/https.")
        if parsed.username or parsed.password:
            raise DomainSecurityError("No se permiten credenciales embebidas en la URL.")
        if not parsed.hostname:
            raise DomainSecurityError("URL sin hostname válido.")

        host = parsed.hostname.strip().lower()
        ip_obj = None
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            ip_obj = None

        if ip_obj is not None:
            is_pub, reason = check_ip_is_public(str(ip_obj))
            if not is_pub:
                raise DomainSecurityError(reason or "IP en URL bloqueada por política SSRF.")
            normalized_domain = str(ip_obj)
        else:
            normalized_domain = validate_hostname_syntax(host)

        return {
            "raw_input": candidate,
            "normalized_target": candidate,
            "normalized_domain": normalized_domain,
            "input_type": IndicatorInputType.URL,
        }

    # 3. Dominio o Subdominio
    clean_host = validate_hostname_syntax(candidate)
    extracted = tldextract.extract(clean_host)
    if not extracted.domain or not extracted.suffix:
        raise DomainSecurityError(f"Dominio sin sufijo público válido: '{clean_host}'.")

    input_type = IndicatorInputType.SUBDOMAIN if extracted.subdomain else IndicatorInputType.DOMAIN
    return {
        "raw_input": candidate,
        "normalized_target": clean_host,
        "normalized_domain": clean_host,
        "registered_domain": f"{extracted.domain}.{extracted.suffix}",
        "input_type": input_type,
    }


def enforce_anti_ssrf_and_dns_rebinding(
    target_host: str,
    authorized_scope: Optional[List[str]] = None,
    resolve_dns: bool = True,
) -> Dict[str, Any]:
    """
    Aplica SecurityGovernanceGuard y protección contra DNS Rebinding:
    si el dominio resuelve a cualquier IP privada/interna/loopback, bloquea la operación.
    """
    guard_res = SecurityGovernanceGuard.validate_target_safety(target_host, authorized_scope=authorized_scope)
    if not guard_res.get("safe"):
        raise DomainSecurityError(guard_res.get("reason", "Objetivo bloqueado por gobernanza de seguridad."))

    resolved_ips: List[str] = []
    try:
        ip_obj = ipaddress.ip_address(target_host)
        is_pub, reason = check_ip_is_public(str(ip_obj))
        if not is_pub:
            raise DomainSecurityError(reason or "IP privada bloqueada.")
        resolved_ips.append(str(ip_obj))
        return {"safe": True, "resolved_ips": resolved_ips}
    except ValueError:
        pass

    if resolve_dns:
        try:
            addr_info = socket.getaddrinfo(target_host, None, proto=socket.IPPROTO_TCP)
            for item in addr_info:
                ip_str = item[4][0]
                if ip_str not in resolved_ips:
                    is_pub, reason = check_ip_is_public(ip_str)
                    if not is_pub:
                        raise DomainSecurityError(
                            f"Posible DNS Rebinding / SSRF detectado: '{target_host}' resolvió a IP no pública {ip_str} ({reason})."
                        )
                    resolved_ips.append(ip_str)
        except socket.gaierror:
            # Un dominio sin resolución DNS actual puede seguir investigándose pasivamente en CTI/WHOIS
            pass

    return {"safe": True, "resolved_ips": resolved_ips}


def validate_outbound_url(url: str) -> str:
    """Valida que una URL externa (p.ej. redirección o bootstrap RDAP) apunte solo a HTTPS público."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise DomainSecurityError(f"URL externa rechazada por política de seguridad: {url}")
    enforce_anti_ssrf_and_dns_rebinding(parsed.hostname, resolve_dns=True)
    return url


class CredentialVault:
    """Cifra y descifra API Keys de proveedores usando Fernet derivado de SECRET_KEY."""

    @staticmethod
    def _get_fernet() -> Fernet:
        digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
        key = base64.urlsafe_b64encode(digest)
        return Fernet(key)

    @classmethod
    def encrypt_key(cls, plain_api_key: str) -> str:
        clean = plain_api_key.strip()
        if not clean:
            raise DomainSecurityError("La API Key no puede estar vacía.")
        return cls._get_fernet().encrypt(clean.encode("utf-8")).decode("utf-8")

    @classmethod
    def decrypt_key(cls, encrypted_api_key: str) -> str:
        try:
            return cls._get_fernet().decrypt(encrypted_api_key.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise DomainSecurityError("No se pudo descifrar la API Key almacenada (SECRET_KEY incompatible).") from exc

    @staticmethod
    def mask_key(plain_api_key: str) -> str:
        clean = plain_api_key.strip()
        if len(clean) <= 8:
            return "****"
        return f"{clean[:4]}...{clean[-4:]}"
