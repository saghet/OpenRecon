"""
Conector oficial para XposedOrNot API v1 (https://api.xposedornot.com/v1/).
Cumple con controles de seguridad:
- Solo HTTPS con validación TLS y follow_redirects=False (anti-SSRF).
- Validación estricta de formato de correo electrónico antes de consultar.
- Gestión segura de API Key opcional (XPOSEDORNOT_API_KEY) sin exposición en logs/respuestas.
- Manejo explícito de estados: COMPLETED, NO_MATCHES, RATE_LIMITED, TEMPORARILY_UNAVAILABLE, TIMEOUT, CONNECTION_ERROR, MALFORMED_RESPONSE.
- Nunca almacena ni transmite contraseñas en texto plano.
"""

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

from app.services.email_intel.zehef_adapter import ZehefAdapter

logger = logging.getLogger("email_intel.xposedornot")

XON_BREACH_ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics"
XON_DOMAIN_BREACHES_URL = "https://api.xposedornot.com/v1/domain-breaches/"
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")

# Mapeo determinista de campos xposed_data a categorías normalizadas
_CATEGORY_MAP = {
    "email": "EMAIL_ADDRESSES",
    "e-mail": "EMAIL_ADDRESSES",
    "name": "FULL_NAMES",
    "username": "USERNAMES",
    "phone": "PHONE_NUMBERS",
    "mobile": "PHONE_NUMBERS",
    "ip": "IP_ADDRESSES",
    "password": "PASSWORDS",
    "hash": "PASSWORD_HASHES",
    "salt": "PASSWORD_HASHES",
    "address": "PERSONAL_INFO",
    "dob": "PERSONAL_INFO",
    "birth": "PERSONAL_INFO",
    "gender": "PERSONAL_INFO",
    "ssn": "PERSONAL_INFO",
    "passport": "PERSONAL_INFO",
    "credit": "FINANCIAL_DATA",
    "bank": "FINANCIAL_DATA",
    "payment": "FINANCIAL_DATA",
    "financial": "FINANCIAL_DATA",
    "company": "CORPORATE_DATA",
    "employer": "CORPORATE_DATA",
    "job": "CORPORATE_DATA",
}


def validate_email_syntax(email: str) -> str:
    clean = (email or "").strip().lower()
    if not clean or len(clean) > 254 or not _EMAIL_RE.match(clean):
        raise ValueError(f"Formato de correo electrónico inválido: '{email}'")
    return clean


def classify_exposed_categories(raw_xposed_data: Any) -> List[str]:
    """Clasifica los tipos de datos reportados por XposedOrNot en categorías normalizadas."""
    if not raw_xposed_data:
        return []
    tokens: List[str] = []
    if isinstance(raw_xposed_data, str):
        tokens = [t.strip() for t in re.split(r"[;,|]", raw_xposed_data) if t.strip()]
    elif isinstance(raw_xposed_data, list):
        tokens = [str(t).strip() for t in raw_xposed_data if str(t).strip()]

    categories: List[str] = []
    for tok in tokens:
        tl = tok.lower()
        matched = False
        for kw, cat in _CATEGORY_MAP.items():
            if kw in tl:
                if cat not in categories:
                    categories.append(cat)
                matched = True
        if not matched and "OTHER_SENSITIVE_DATA" not in categories:
            categories.append("OTHER_SENSITIVE_DATA")
    return categories


class XposedOrNotConnector:
    """Conector asíncrono hacia la API oficial de XposedOrNot con caché TTL configurable."""

    _EMAIL_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    def __init__(self, adapter: Optional[ZehefAdapter] = None, timeout: float = 10.0, cache_ttl_seconds: int = 1800):
        self.adapter = adapter or ZehefAdapter(timeout_seconds=timeout)
        self.timeout = timeout
        self.cache_ttl_seconds = cache_ttl_seconds

    @classmethod
    def clear_cache(cls) -> None:
        cls._EMAIL_CACHE.clear()

    async def search_email(self, target_email: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Consulta /v1/breach-analytics?email=... y retorna estructura normalizada
        con estado explícito, hallazgos y evidencia criptográfica.
        """
        queried_at = datetime.now(timezone.utc).isoformat()
        try:
            clean_email = validate_email_syntax(target_email)
        except ValueError as exc:
            return {
                "source": "XposedOrNot",
                "status": "INVALID_INPUT",
                "queried_at": queried_at,
                "error": str(exc),
                "findings": [],
                "evidence": {
                    "source_type": "BREACH_XPOSEDORNOT",
                    "source_name": "XposedOrNot",
                    "collected_at_utc": queried_at,
                    "raw_content_preview": str(exc),
                    "content_sha256": self.adapter.calculate_sha256(str(exc)),
                    "validation_status": "ERROR",
                    "confidence_score": 0.0,
                },
            }

        if use_cache and self.cache_ttl_seconds > 0 and clean_email in self._EMAIL_CACHE:
            cached_ts, cached_res = self._EMAIL_CACHE[clean_email]
            if (datetime.now(timezone.utc).timestamp() - cached_ts) < self.cache_ttl_seconds:
                copied = dict(cached_res)
                copied["from_cache"] = True
                return copied

        headers = {
            "Accept": "application/json",
            "User-Agent": "OpenRecon-EmailIntel/1.0",
        }
        api_key = os.getenv("XPOSEDORNOT_API_KEY")
        if api_key:
            headers["x-api-key"] = api_key.strip()

        url = f"{XON_BREACH_ANALYTICS_URL}?email={quote(clean_email)}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                verify=True,
            ) as client:
                resp = await client.get(url, headers=headers)

            raw_text = resp.text or ""
            sha256 = self.adapter.calculate_sha256(raw_text)

            if resp.status_code == 404:
                res = self._no_matches_result(queried_at, raw_text, sha256)
                if use_cache and self.cache_ttl_seconds > 0:
                    self._EMAIL_CACHE[clean_email] = (datetime.now(timezone.utc).timestamp(), res)
                return res

            if resp.status_code == 429:
                return self._error_result(
                    "RATE_LIMITED",
                    "Límite de consultas alcanzado en XposedOrNot (HTTP 429).",
                    queried_at,
                    raw_text,
                    sha256,
                )

            if resp.status_code >= 500:
                return self._error_result(
                    "TEMPORARILY_UNAVAILABLE",
                    f"XposedOrNot temporalmente no disponible (HTTP {resp.status_code}).",
                    queried_at,
                    raw_text,
                    sha256,
                )

            if resp.status_code != 200:
                return self._error_result(
                    "CONNECTION_ERROR",
                    f"Respuesta inesperada de XposedOrNot (HTTP {resp.status_code}).",
                    queried_at,
                    raw_text,
                    sha256,
                )

            try:
                payload = resp.json()
                if not isinstance(payload, dict):
                    raise ValueError("Payload JSON no es un objeto")
            except ValueError:
                return self._error_result(
                    "MALFORMED_RESPONSE",
                    "Respuesta JSON malformada o incompleta de XposedOrNot.",
                    queried_at,
                    raw_text,
                    sha256,
                )

            if payload.get("Error") == "Not found":
                res = self._no_matches_result(queried_at, raw_text, sha256)
                if use_cache and self.cache_ttl_seconds > 0:
                    self._EMAIL_CACHE[clean_email] = (datetime.now(timezone.utc).timestamp(), res)
                return res

            exposed = payload.get("ExposedBreaches")
            if not isinstance(exposed, dict) or not isinstance(exposed.get("breaches_details"), list):
                summary = payload.get("BreachesSummary")
                if isinstance(summary, dict) and not summary.get("site"):
                    return self._no_matches_result(queried_at, raw_text, sha256)
                return self._error_result(
                    "MALFORMED_RESPONSE",
                    "Estructura ExposedBreaches ausente o inesperada en XposedOrNot.",
                    queried_at,
                    raw_text,
                    sha256,
                )

            details_list = exposed.get("breaches_details", [])
            if not details_list:
                return self._no_matches_result(queried_at, raw_text, sha256)

            findings: List[Dict[str, Any]] = []
            seen_keys = set()

            for item in details_list:
                if not isinstance(item, dict):
                    continue
                breach_name = str(item.get("breach") or "Unknown Breach").strip()
                domain = str(item.get("domain") or "").strip().lower()
                xposed_date = str(item.get("xposed_date") or "Unknown").strip()
                dedup_key = (breach_name.lower(), domain, xposed_date)
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                categories = classify_exposed_categories(item.get("xposed_data"))
                password_risk = str(item.get("password_risk") or "").lower()
                if password_risk in ("plaintext", "easytocrack", "hardtocrack") and "PASSWORDS" not in categories and "PASSWORD_HASHES" not in categories:
                    categories.append("PASSWORDS" if password_risk == "plaintext" else "PASSWORD_HASHES")

                confidence = "HIGH" if item.get("verified") is True else "MEDIUM"
                ref_url = str(item.get("references") or f"https://xposedornot.com/xposed#{quote(breach_name)}").strip()

                findings.append({
                    "source": f"XposedOrNot · {breach_name}",
                    "provider": "XposedOrNot",
                    "breach_name": breach_name,
                    "affected_domain": domain or None,
                    "industry": item.get("industry"),
                    "leak_date": xposed_date,
                    "query_date": queried_at,
                    "exposed_data_types": categories or ["EMAIL_ADDRESSES"],
                    "raw_exposed_data": item.get("xposed_data"),
                    "password_risk": password_risk or None,
                    "description": (item.get("details") or "")[:400],
                    "confidence_level": confidence,
                    "verifiable_reference": ref_url,
                    "corporate_services_count": 0,
                    "user_services_count": 0,
                    "computer_name_preview": domain or breach_name,
                    "operating_system": item.get("industry") or "Breach Disclosure",
                    "ip_address_preview": f"{item.get('xposed_records', 'N/D')} reg.",
                    "raw_evidence_sha256": sha256,
                })

            result = {
                "source": "XposedOrNot",
                "status": "COMPLETED",
                "from_cache": False,
                "queried_at": queried_at,
                "matches_count": len(findings),
                "findings": findings,
                "evidence": {
                    "source_type": "BREACH_XPOSEDORNOT",
                    "source_name": "XposedOrNot",
                    "collected_at_utc": queried_at,
                    "raw_content_preview": raw_text[:800],
                    "content_sha256": sha256,
                    "validation_status": "CORROBORATED",
                    "confidence_score": 0.90,
                },
            }
            if use_cache and self.cache_ttl_seconds > 0:
                self._EMAIL_CACHE[clean_email] = (datetime.now(timezone.utc).timestamp(), result)
            return result

        except httpx.TimeoutException:
            msg = "Tiempo de espera agotado consultando XposedOrNot."
            return self._error_result("TIMEOUT", msg, queried_at, msg, self.adapter.calculate_sha256(msg))
        except httpx.RequestError as exc:
            msg = f"Error de conexión con XposedOrNot: {exc}"
            return self._error_result("CONNECTION_ERROR", msg, queried_at, msg, self.adapter.calculate_sha256(msg))
        except Exception as exc:
            msg = f"Error inesperado en XposedOrNot: {exc}"
            return self._error_result("CONNECTION_ERROR", msg, queried_at, msg, self.adapter.calculate_sha256(msg))

    def _no_matches_result(self, queried_at: str, raw_text: str, sha256: str) -> Dict[str, Any]:
        return {
            "source": "XposedOrNot",
            "status": "NO_MATCHES",
            "queried_at": queried_at,
            "matches_count": 0,
            "findings": [],
            "evidence": {
                "source_type": "BREACH_XPOSEDORNOT",
                "source_name": "XposedOrNot",
                "collected_at_utc": queried_at,
                "raw_content_preview": raw_text[:500] or "Not found in XposedOrNot",
                "content_sha256": sha256,
                "validation_status": "NO_MATCHES",
                "confidence_score": 0.90,
            },
        }

    @staticmethod
    def _error_result(
        status: str, message: str, queried_at: str, raw_text: str, sha256: str
    ) -> Dict[str, Any]:
        return {
            "source": "XposedOrNot",
            "status": status,
            "queried_at": queried_at,
            "error": message,
            "matches_count": 0,
            "findings": [],
            "evidence": {
                "source_type": "BREACH_XPOSEDORNOT",
                "source_name": "XposedOrNot",
                "collected_at_utc": queried_at,
                "raw_content_preview": (raw_text or message)[:500],
                "content_sha256": sha256,
                "validation_status": status,
                "confidence_score": 0.0,
            },
        }

    async def query_domain_breaches(self, api_key: Optional[str] = None) -> Dict[str, Any]:
        """Query XposedOrNot Enterprise / CXO domain-breaches API with x-api-key."""
        queried_at = datetime.now(timezone.utc).isoformat()
        resolved_key = (api_key or os.getenv("XPOSEDORNOT_API_KEY") or "").strip()
        if not resolved_key:
            return {
                "source": "XposedOrNot",
                "endpoint": "domain-breaches",
                "status": "KEY_NOT_CONFIGURED",
                "queried_at": queried_at,
                "error": "XPOSEDORNOT_API_KEY no configurada.",
                "data": None,
            }

        headers = {
            "User-Agent": "OpenRecon-EmailIntel/1.0",
            "Accept": "application/json",
            "x-api-key": resolved_key,
            "Content-Length": "0",
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=True, follow_redirects=False) as client:
                resp = await client.post(XON_DOMAIN_BREACHES_URL, headers=headers)
        except httpx.TimeoutException:
            return {
                "source": "XposedOrNot",
                "endpoint": "domain-breaches",
                "status": "TIMEOUT",
                "queried_at": queried_at,
                "error": "Timeout consultando XposedOrNot domain-breaches.",
                "data": None,
            }
        except httpx.RequestError as exc:
            return {
                "source": "XposedOrNot",
                "endpoint": "domain-breaches",
                "status": "CONNECTION_ERROR",
                "queried_at": queried_at,
                "error": f"Error de conexión con XposedOrNot: {type(exc).__name__}",
                "data": None,
            }

        if resp.status_code == 200:
            try:
                payload = resp.json()
            except ValueError:
                return {
                    "source": "XposedOrNot",
                    "endpoint": "domain-breaches",
                    "status": "PARTIAL",
                    "queried_at": queried_at,
                    "error": "Respuesta JSON inválida de XposedOrNot domain-breaches.",
                    "data": None,
                }
            return {
                "source": "XposedOrNot",
                "endpoint": "domain-breaches",
                "status": "COMPLETED",
                "queried_at": queried_at,
                "error": None,
                "data": payload,
            }
        if resp.status_code in (401, 403, 422):
            return {
                "source": "XposedOrNot",
                "endpoint": "domain-breaches",
                "status": "INVALID_KEY",
                "queried_at": queried_at,
                "error": f"XposedOrNot rechazó la API key (HTTP {resp.status_code}).",
                "data": None,
            }
        if resp.status_code == 429:
            return {
                "source": "XposedOrNot",
                "endpoint": "domain-breaches",
                "status": "RATE_LIMITED",
                "queried_at": queried_at,
                "error": "Límite de consultas alcanzado en XposedOrNot (HTTP 429).",
                "data": None,
            }
        if resp.status_code >= 500:
            return {
                "source": "XposedOrNot",
                "endpoint": "domain-breaches",
                "status": "TEMPORARILY_UNAVAILABLE",
                "queried_at": queried_at,
                "error": f"XposedOrNot no disponible temporalmente (HTTP {resp.status_code}).",
                "data": None,
            }
        return {
            "source": "XposedOrNot",
            "endpoint": "domain-breaches",
            "status": "PARTIAL",
            "queried_at": queried_at,
            "error": f"Respuesta inesperada de XposedOrNot (HTTP {resp.status_code}).",
            "data": None,
        }
