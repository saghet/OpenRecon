"""
Adaptadores independientes de Domain Intelligence inspirados en WebOSINT (MIT License)
y ampliados con enriquecimiento EPSS/CISA KEV, postura DNS completa y correlación
con Email Intelligence.

Principios de seguridad y calidad:
- Todas las peticiones HTTP externas pasan por safe_http_get_with_retry (anti-SSRF).
- Solo se cachean respuestas válidas (SUCCESS / NO_DATA); nunca errores transitorios.
- Infraestructura compartida (CDN/cloud/hosting) se marca explícitamente para evitar falsos positivos.
"""

import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import dns.asyncresolver
import dns.exception
import httpx

from app.core.domain_security import DomainSecurityError
from app.models.domain_intel import IndicatorInputType, ProviderQueryStatus
from app.services.domain_intel.base import (
    DomainIntelCache,
    ProviderResponse,
    safe_http_get_with_retry,
)

SHARED_HOSTING_KEYWORDS = (
    "cloudflare",
    "akamai",
    "fastly",
    "cloudfront",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "digitalocean",
    "ovh",
    "hetzner",
    "linode",
    "vercel",
    "netlify",
    "incapsula",
    "imperva",
    "sucuri",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_shared_provider(text: str) -> bool:
    low = (text or "").lower()
    return any(k in low for k in SHARED_HOSTING_KEYWORDS)


class ShodanInternetDBConnector:
    """Adaptador pasivo para Shodan InternetDB (puertos, hostnames, CPE, CVE, tags)."""

    def __init__(self, cache: Optional[DomainIntelCache] = None):
        self.cache = cache or DomainIntelCache("shodan_internetdb")

    async def query(self, ip: Optional[str]) -> ProviderResponse:
        t0 = time.perf_counter()
        if not ip:
            return ProviderResponse(
                provider_name="shodan_internetdb",
                status=ProviderQueryStatus.NO_DATA,
                error_message="No se resolvió una IPv4/IPv6 para consultar Shodan InternetDB.",
                latency_ms=0,
            )

        cached = self.cache.get(ip)
        if cached is not None:
            return ProviderResponse(
                provider_name="shodan_internetdb",
                status=ProviderQueryStatus.SUCCESS,
                data=cached,
                from_cache=True,
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )

        url = f"https://internetdb.shodan.io/{ip}"
        try:
            resp = await safe_http_get_with_retry(url, timeout=8.0)
            lat = int((time.perf_counter() - t0) * 1000)
            if resp.status_code == 404:
                return ProviderResponse(
                    provider_name="shodan_internetdb",
                    status=ProviderQueryStatus.NO_DATA,
                    data={"ip": ip, "ports": [], "cpes": [], "vulns": [], "hostnames": [], "tags": []},
                    latency_ms=lat,
                )
            if resp.status_code == 429:
                return ProviderResponse(
                    provider_name="shodan_internetdb",
                    status=ProviderQueryStatus.RATE_LIMITED,
                    error_message="Shodan InternetDB rate limit (HTTP 429).",
                    latency_ms=lat,
                )
            if resp.status_code >= 400:
                return ProviderResponse(
                    provider_name="shodan_internetdb",
                    status=ProviderQueryStatus.CONNECTION_ERROR,
                    error_message=f"Shodan InternetDB HTTP {resp.status_code}.",
                    latency_ms=lat,
                )

            payload = resp.json()
            data = {
                "source": "shodan_internetdb",
                "queried_at": _now_iso(),
                "observed_at": _now_iso(),
                "ip": payload.get("ip", ip),
                "ports": payload.get("ports", []) or [],
                "hostnames": payload.get("hostnames", []) or [],
                "cpes": payload.get("cpes", []) or [],
                "vulns": payload.get("vulns", []) or [],
                "tags": payload.get("tags", []) or [],
                "confidence": 85,
                "raw_evidence": payload,
            }
            self.cache.set(ip, data, ttl_seconds=1800)
            return ProviderResponse(
                provider_name="shodan_internetdb",
                status=ProviderQueryStatus.SUCCESS,
                data=data,
                latency_ms=lat,
            )
        except httpx.TimeoutException:
            return ProviderResponse("shodan_internetdb", ProviderQueryStatus.TIMEOUT, error_message="Timeout Shodan InternetDB")
        except (httpx.RequestError, DomainSecurityError) as exc:
            return ProviderResponse("shodan_internetdb", ProviderQueryStatus.CONNECTION_ERROR, error_message=str(exc))
        except ValueError:
            return ProviderResponse("shodan_internetdb", ProviderQueryStatus.MALFORMED_RESPONSE, error_message="JSON inválido de Shodan InternetDB")


class EPSSAndKEVEnricher:
    """Enriquece CVEs con FIRST EPSS y catálogo CISA KEV para mitigar falsos positivos."""

    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, cache: Optional[DomainIntelCache] = None):
        self.cache = cache or DomainIntelCache("epss_kev")

    async def _get_kev_set(self) -> Dict[str, Dict[str, Any]]:
        cached = self.cache.get("cisa_kev_map")
        if isinstance(cached, dict):
            return cached
        try:
            resp = await safe_http_get_with_retry(self.CISA_KEV_URL, timeout=12.0, max_retries=1)
            if resp.status_code == 200:
                vulns = resp.json().get("vulnerabilities", []) or []
                kev_map = {
                    v["cveID"]: {
                        "vendorProject": v.get("vendorProject"),
                        "product": v.get("product"),
                        "dueDate": v.get("dueDate"),
                        "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse"),
                    }
                    for v in vulns
                    if isinstance(v, dict) and v.get("cveID")
                }
                self.cache.set("cisa_kev_map", kev_map, ttl_seconds=43200)
                return kev_map
        except Exception:
            pass
        return {}

    async def enrich_cves(self, cves: List[str]) -> ProviderResponse:
        t0 = time.perf_counter()
        clean_cves = sorted({c.strip().upper() for c in (cves or []) if c and c.strip().upper().startswith("CVE-")})[:40]
        if not clean_cves:
            return ProviderResponse(
                provider_name="epss_kev",
                status=ProviderQueryStatus.NO_DATA,
                data={"enriched_cves": [], "kev_count": 0, "high_epss_count": 0},
                latency_ms=0,
            )

        kev_map = await self._get_kev_set()
        epss_scores: Dict[str, Dict[str, float]] = {}
        try:
            resp = await safe_http_get_with_retry(
                self.EPSS_URL,
                params={"cve": ",".join(clean_cves)},
                timeout=10.0,
                max_retries=1,
            )
            if resp.status_code == 200:
                for row in resp.json().get("data", []) or []:
                    cve_id = (row.get("cve") or "").upper()
                    if cve_id:
                        epss_scores[cve_id] = {
                            "epss": float(row.get("epss", 0.0)),
                            "percentile": float(row.get("percentile", 0.0)),
                        }
        except Exception:
            pass

        enriched: List[Dict[str, Any]] = []
        kev_count = 0
        high_epss_count = 0
        for cve_id in clean_cves:
            in_kev = cve_id in kev_map
            if in_kev:
                kev_count += 1
            ep = epss_scores.get(cve_id, {})
            epss_val = ep.get("epss", 0.0)
            if epss_val >= 0.2:
                high_epss_count += 1
            likely_fp = (not in_kev) and (epss_val < 0.05)
            enriched.append({
                "cve": cve_id,
                "epss": round(epss_val, 5),
                "percentile": round(ep.get("percentile", 0.0), 4),
                "in_cisa_kev": in_kev,
                "kev_detail": kev_map.get(cve_id),
                "likely_false_positive_or_low_priority": likely_fp,
            })

        return ProviderResponse(
            provider_name="epss_kev",
            status=ProviderQueryStatus.SUCCESS,
            data={
                "source": "epss_kev",
                "queried_at": _now_iso(),
                "observed_at": _now_iso(),
                "enriched_cves": enriched,
                "kev_count": kev_count,
                "high_epss_count": high_epss_count,
                "confidence": 90,
            },
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )


class CertSpotterConnector:
    """Adaptador Certificate Transparency vía Cert Spotter (complemento/fallback de crt.sh)."""

    def __init__(self, cache: Optional[DomainIntelCache] = None):
        self.cache = cache or DomainIntelCache("cert_spotter")

    async def query(self, domain: str, api_key: Optional[str] = None) -> ProviderResponse:
        t0 = time.perf_counter()
        cached = self.cache.get(domain)
        if cached is not None:
            return ProviderResponse(
                provider_name="cert_spotter",
                status=ProviderQueryStatus.SUCCESS,
                data=cached,
                from_cache=True,
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )

        url = "https://api.certspotter.com/v1/issuances"
        headers: Dict[str, str] = {"Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key.strip()}"
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": ["dns_names", "issuer"],
        }
        try:
            resp = await safe_http_get_with_retry(url, headers=headers, params=params, timeout=12.0)
            lat = int((time.perf_counter() - t0) * 1000)
            if resp.status_code == 429:
                return ProviderResponse("cert_spotter", ProviderQueryStatus.RATE_LIMITED, error_message="Cert Spotter HTTP 429", latency_ms=lat)
            if resp.status_code in (401, 403):
                return ProviderResponse("cert_spotter", ProviderQueryStatus.INVALID_KEY, error_message=f"Cert Spotter HTTP {resp.status_code}", latency_ms=lat)
            if resp.status_code >= 400:
                return ProviderResponse("cert_spotter", ProviderQueryStatus.CONNECTION_ERROR, error_message=f"Cert Spotter HTTP {resp.status_code}", latency_ms=lat)

            rows = resp.json()
            if not isinstance(rows, list):
                return ProviderResponse("cert_spotter", ProviderQueryStatus.MALFORMED_RESPONSE, error_message="Respuesta inesperada Cert Spotter", latency_ms=lat)

            subdomains = set()
            certs: List[Dict[str, Any]] = []
            for item in rows[:40]:
                dns_names = item.get("dns_names") or []
                for name in dns_names:
                    clean = str(name).strip().lstrip("*.").lower()
                    if clean.endswith(domain):
                        subdomains.add(clean)
                issuer_obj = item.get("issuer") or {}
                certs.append({
                    "id": item.get("id"),
                    "tbs_sha256": item.get("tbs_sha256"),
                    "not_before": item.get("not_before"),
                    "not_after": item.get("not_after"),
                    "issuer_name": issuer_obj.get("name") if isinstance(issuer_obj, dict) else str(issuer_obj),
                    "dns_names": dns_names[:10],
                })

            data = {
                "source": "cert_spotter",
                "queried_at": _now_iso(),
                "observed_at": _now_iso(),
                "subdomains": sorted(subdomains)[:100],
                "certificates": certs[:25],
                "total_issuances": len(rows),
                "confidence": 85,
            }
            self.cache.set(domain, data, ttl_seconds=1800)
            return ProviderResponse("cert_spotter", ProviderQueryStatus.SUCCESS, data=data, latency_ms=lat)
        except httpx.TimeoutException:
            return ProviderResponse("cert_spotter", ProviderQueryStatus.TIMEOUT, error_message="Timeout Cert Spotter")
        except (httpx.RequestError, DomainSecurityError) as exc:
            return ProviderResponse("cert_spotter", ProviderQueryStatus.CONNECTION_ERROR, error_message=str(exc))
        except ValueError:
            return ProviderResponse("cert_spotter", ProviderQueryStatus.MALFORMED_RESPONSE, error_message="JSON inválido Cert Spotter")


class IPASNConnector:
    """Enriquecimiento IP / ASN / Geolocalización y detección de infraestructura compartida."""

    def __init__(self, cache: Optional[DomainIntelCache] = None):
        self.cache = cache or DomainIntelCache("ip_asn")

    async def query(self, ip: Optional[str]) -> ProviderResponse:
        t0 = time.perf_counter()
        if not ip:
            return ProviderResponse("ip_asn", ProviderQueryStatus.NO_DATA, error_message="Sin IP para consultar ASN.")

        cached = self.cache.get(ip)
        if cached is not None:
            return ProviderResponse("ip_asn", ProviderQueryStatus.SUCCESS, data=cached, from_cache=True, latency_ms=int((time.perf_counter() - t0) * 1000))

        try:
            resp = await safe_http_get_with_retry(f"https://ipinfo.io/{ip}/json", timeout=8.0, max_retries=1)
            lat = int((time.perf_counter() - t0) * 1000)
            if resp.status_code == 200:
                j = resp.json()
                org = j.get("org") or ""
                asn = org.split()[0] if org.startswith("AS") else None
                data = {
                    "source": "ipinfo",
                    "queried_at": _now_iso(),
                    "observed_at": _now_iso(),
                    "ip": ip,
                    "asn": asn,
                    "org": org,
                    "country": j.get("country"),
                    "city": j.get("city"),
                    "is_shared_infrastructure": _is_shared_provider(org),
                    "confidence": 85,
                    "raw_evidence": j,
                }
                self.cache.set(ip, data, ttl_seconds=3600)
                return ProviderResponse("ip_asn", ProviderQueryStatus.SUCCESS, data=data, latency_ms=lat)
            if resp.status_code == 429:
                return ProviderResponse("ip_asn", ProviderQueryStatus.RATE_LIMITED, error_message="ipinfo.io HTTP 429", latency_ms=lat)
            return ProviderResponse("ip_asn", ProviderQueryStatus.CONNECTION_ERROR, error_message=f"ipinfo.io HTTP {resp.status_code}", latency_ms=lat)
        except httpx.TimeoutException:
            return ProviderResponse("ip_asn", ProviderQueryStatus.TIMEOUT, error_message="Timeout ipinfo.io")
        except (httpx.RequestError, DomainSecurityError) as exc:
            return ProviderResponse("ip_asn", ProviderQueryStatus.CONNECTION_ERROR, error_message=str(exc))
        except ValueError:
            return ProviderResponse("ip_asn", ProviderQueryStatus.MALFORMED_RESPONSE, error_message="JSON inválido ipinfo.io")


class DNSSecurityConnector:
    """Evaluación pasiva de postura DNS: SPF, DMARC, DKIM, DNSSEC, CAA, MX y NS."""

    COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail", "dkim")

    async def query(self, domain: str, input_type: IndicatorInputType) -> ProviderResponse:
        t0 = time.perf_counter()
        if input_type in (IndicatorInputType.IPV4, IndicatorInputType.IPV6):
            return ProviderResponse("dns_security", ProviderQueryStatus.NO_DATA, error_message="Postura DNS aplica a dominios.")

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 3.0

        async def _txt(name: str) -> List[str]:
            try:
                ans = await resolver.resolve(name, "TXT")
                return ["".join(s.decode("utf-8", "ignore") for s in r.strings) for r in ans]
            except Exception:
                return []

        async def _exists(name: str, rtype: str) -> List[str]:
            try:
                ans = await resolver.resolve(name, rtype)
                return [r.to_text() for r in ans]
            except Exception:
                return []

        root_txts = await _txt(domain)
        spf_records = [t for t in root_txts if t.lower().startswith("v=spf1")]
        dmarc_records = [t for t in await _txt(f"_dmarc.{domain}") if "v=dmarc1" in t.lower()]
        caa_records = await _exists(domain, "CAA")
        dnskey_records = await _exists(domain, "DNSKEY")
        ds_records = await _exists(domain, "DS")
        mx_records = await _exists(domain, "MX")
        ns_records = await _exists(domain, "NS")

        dkim_found: List[Dict[str, str]] = []
        for sel in self.COMMON_DKIM_SELECTORS:
            recs = await _txt(f"{sel}._domainkey.{domain}")
            for rec in recs:
                if "v=dkim1" in rec.lower() or "p=" in rec.lower():
                    dkim_found.append({"selector": sel, "record_preview": rec[:120]})
                    break

        score = 0
        if spf_records:
            score += 25
        if dmarc_records:
            score += 30
        if dkim_found:
            score += 20
        if dnskey_records or ds_records:
            score += 15
        if caa_records:
            score += 10

        return ProviderResponse(
            provider_name="dns_security",
            status=ProviderQueryStatus.SUCCESS,
            data={
                "source": "dns_security",
                "queried_at": _now_iso(),
                "observed_at": _now_iso(),
                "spf": {"present": bool(spf_records), "records": spf_records},
                "dmarc": {"present": bool(dmarc_records), "records": dmarc_records},
                "dkim": {"present": bool(dkim_found), "selectors_found": dkim_found},
                "dnssec": {"enabled": bool(dnskey_records or ds_records), "dnskey_count": len(dnskey_records), "ds_count": len(ds_records)},
                "caa": {"present": bool(caa_records), "records": caa_records},
                "mx_count": len(mx_records),
                "ns_count": len(ns_records),
                "dns_security_score": score,
                "confidence": 95,
            },
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )


class DomainExposureConnector:
    """Correlaciona exposición del dominio con Email Intelligence local y LunarCyber."""

    def __init__(self, sqlite_path: Optional[str] = None):
        self.sqlite_path = sqlite_path or self._resolve_email_intel_sqlite()

    @staticmethod
    def _resolve_email_intel_sqlite() -> str:
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.abspath(os.path.join(here, "..", "..", "..", ".."))
        return os.path.join(root, "web_dashboard", "openrecon.sqlite")

    def _query_local_email_intel(self, domain: str) -> Dict[str, Any]:
        if not os.path.exists(self.sqlite_path):
            return {"investigated_emails": [], "leaks": [], "total_leaks": 0}
        try:
            conn = sqlite3.connect(self.sqlite_path)
            conn.row_factory = sqlite3.Row
            invs = conn.execute(
                """
                SELECT id, target_email, risk_level, exposure_score, created_at
                FROM email_intel_investigations
                WHERE lower(target_email) LIKE ? AND status = 'COMPLETED'
                ORDER BY created_at DESC LIMIT 20
                """,
                (f"%@{domain.lower()}",),
            ).fetchall()
            inv_ids = [r["id"] for r in invs]
            leaks: List[Dict[str, Any]] = []
            if inv_ids:
                placeholders = ",".join("?" for _ in inv_ids)
                leak_rows = conn.execute(
                    f"""
                    SELECT investigation_id, source, leak_date, exposed_data_types, verifiable_reference
                    FROM email_intel_leaks
                    WHERE investigation_id IN ({placeholders})
                    LIMIT 50
                    """,
                    inv_ids,
                ).fetchall()
                leaks = [dict(r) for r in leak_rows]
            conn.close()
            return {
                "investigated_emails": [dict(r) for r in invs],
                "leaks": leaks,
                "total_leaks": len(leaks),
            }
        except Exception:
            return {"investigated_emails": [], "leaks": [], "total_leaks": 0}

    async def query(self, domain: str, query_external: bool = True) -> ProviderResponse:
        t0 = time.perf_counter()
        local_corr = self._query_local_email_intel(domain)
        external_status = "SKIPPED"
        external_data: Dict[str, Any] = {}

        if query_external:
            try:
                resp = await safe_http_get_with_retry(
                    "https://api.lunarcyber.com/domain-exposure",
                    params={"domain": domain},
                    timeout=8.0,
                    max_retries=1,
                )
                if resp.status_code == 200:
                    external_status = "SUCCESS"
                    external_data = resp.json() if resp.text else {}
                elif resp.status_code == 404:
                    external_status = "NO_DATA"
                elif resp.status_code == 429:
                    external_status = "RATE_LIMITED"
                else:
                    external_status = f"HTTP_{resp.status_code}"
            except httpx.TimeoutException:
                external_status = "TIMEOUT"
            except Exception as exc:
                external_status = f"CONNECTION_ERROR:{type(exc).__name__}"

        return ProviderResponse(
            provider_name="domain_exposure",
            status=ProviderQueryStatus.SUCCESS,
            data={
                "source": "domain_exposure",
                "queried_at": _now_iso(),
                "observed_at": _now_iso(),
                "email_intel_correlation": local_corr,
                "lunarcyber_status": external_status,
                "lunarcyber_data": external_data,
                "confidence": 85 if local_corr["total_leaks"] > 0 or external_status == "SUCCESS" else 60,
            },
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )


class WhoisFreaksHistoryConnector:
    """Historial WHOIS vía WhoisFreaks (requiere WHOIS_FREAKS_API_KEY)."""

    async def query(self, domain: str, api_key: Optional[str] = None) -> ProviderResponse:
        t0 = time.perf_counter()
        resolved_key = (api_key or os.getenv("WHOIS_FREAKS_API_KEY") or "").strip()
        if not resolved_key:
            return ProviderResponse(
                provider_name="whois_history",
                status=ProviderQueryStatus.KEY_NOT_CONFIGURED,
                error_message="WHOIS_FREAKS_API_KEY no configurada (omitido por configuración).",
                latency_ms=0,
            )

        url = "https://api.whoisfreaks.com/v1.0/whois"
        params = {"apiKey": resolved_key, "whois": "historical", "domainName": domain}
        try:
            resp = await safe_http_get_with_retry(url, params=params, timeout=10.0, max_retries=1)
            lat = int((time.perf_counter() - t0) * 1000)
            if resp.status_code in (401, 403):
                return ProviderResponse("whois_history", ProviderQueryStatus.INVALID_KEY, error_message=f"WhoisFreaks HTTP {resp.status_code}", latency_ms=lat)
            if resp.status_code == 429:
                return ProviderResponse("whois_history", ProviderQueryStatus.RATE_LIMITED, error_message="WhoisFreaks HTTP 429", latency_ms=lat)
            if resp.status_code >= 400:
                return ProviderResponse("whois_history", ProviderQueryStatus.CONNECTION_ERROR, error_message=f"WhoisFreaks HTTP {resp.status_code}", latency_ms=lat)

            payload = resp.json()
            records = payload.get("whois_domains_historical") or []
            return ProviderResponse(
                provider_name="whois_history",
                status=ProviderQueryStatus.SUCCESS if records else ProviderQueryStatus.NO_DATA,
                data={
                    "source": "whois_history",
                    "queried_at": _now_iso(),
                    "observed_at": _now_iso(),
                    "total_records": len(records),
                    "records": records[:20],
                    "confidence": 85,
                },
                latency_ms=lat,
            )
        except httpx.TimeoutException:
            return ProviderResponse("whois_history", ProviderQueryStatus.TIMEOUT, error_message="Timeout WhoisFreaks")
        except (httpx.RequestError, DomainSecurityError) as exc:
            return ProviderResponse("whois_history", ProviderQueryStatus.CONNECTION_ERROR, error_message=str(exc))
        except ValueError:
            return ProviderResponse("whois_history", ProviderQueryStatus.MALFORMED_RESPONSE, error_message="JSON inválido WhoisFreaks")
