import asyncio
import json
import logging
import socket
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import dns.exception
import dns.resolver
import dns.reversename
import httpx

from app.core.domain_security import DomainSecurityError, validate_hostname_syntax
from app.models.domain_intel import IndicatorInputType, ProviderQueryStatus
from app.services.cti.feed_adapters import AbuseIPDBAdapter, ThreatFoxAdapter, URLhausAdapter
from app.services.domain_intel.base import ProviderResponse, safe_http_get

logger = logging.getLogger("domain_intel.connectors")


class RDAPWhoisConnector:
    """
    Conector RDAP (prioritario) con fallback a WHOIS TCP puerto 43.
    Diferencia datos no disponibles de inexistentes.
    """

    PROVIDER = "rdap_whois"

    async def query(self, target: str, input_type: IndicatorInputType, timeout: float = 10.0) -> ProviderResponse:
        start = time.monotonic()
        is_ip = input_type in (IndicatorInputType.IPV4, IndicatorInputType.IPV6)
        rdap_url = f"https://rdap.org/ip/{target}" if is_ip else f"https://rdap.org/domain/{target}"

        try:
            resp = await safe_http_get(
                rdap_url,
                headers={"Accept": "application/rdap+json, application/json"},
                timeout=timeout,
                max_redirects=3,
            )
            latency = int((time.monotonic() - start) * 1000)

            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except ValueError:
                    return ProviderResponse(
                        provider_name=self.PROVIDER,
                        status=ProviderQueryStatus.MALFORMED_RESPONSE,
                        error_message="Respuesta RDAP no es JSON válido.",
                        latency_ms=latency,
                    )
                parsed = self._parse_rdap(payload)
                return ProviderResponse(
                    provider_name=self.PROVIDER,
                    status=ProviderQueryStatus.SUCCESS,
                    data=parsed,
                    latency_ms=latency,
                )
            if resp.status_code == 404:
                # Intentar fallback WHOIS para dominios si RDAP no lo tiene
                if not is_ip:
                    whois_data = await self._whois_fallback(target, timeout=timeout)
                    if whois_data is not None:
                        return ProviderResponse(
                            provider_name=self.PROVIDER,
                            status=ProviderQueryStatus.SUCCESS,
                            data=whois_data,
                            latency_ms=int((time.monotonic() - start) * 1000),
                        )
                return ProviderResponse(
                    provider_name=self.PROVIDER,
                    status=ProviderQueryStatus.NO_DATA,
                    data={"source_protocol": "RDAP", "exists": False},
                    latency_ms=latency,
                )
            if resp.status_code == 429:
                return ProviderResponse(
                    provider_name=self.PROVIDER,
                    status=ProviderQueryStatus.RATE_LIMITED,
                    error_message="Límite de solicitudes alcanzado en RDAP.",
                    latency_ms=latency,
                )
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=f"RDAP HTTP {resp.status_code}",
                latency_ms=latency,
            )
        except httpx.TimeoutException:
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.TIMEOUT,
                error_message="Tiempo de espera agotado consultando RDAP.",
                latency_ms=int((time.monotonic() - start) * 1000),
            )
        except DomainSecurityError as exc:
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=str(exc),
                latency_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as exc:
            if not is_ip:
                whois_data = await self._whois_fallback(target, timeout=timeout)
                if whois_data is not None:
                    return ProviderResponse(
                        provider_name=self.PROVIDER,
                        status=ProviderQueryStatus.SUCCESS,
                        data=whois_data,
                        latency_ms=int((time.monotonic() - start) * 1000),
                    )
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=f"Error RDAP/WHOIS: {exc}",
                latency_ms=int((time.monotonic() - start) * 1000),
            )

    def _parse_rdap(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        events = {e.get("eventAction"): e.get("eventDate") for e in payload.get("events", []) if isinstance(e, dict)}
        nameservers = [
            ns.get("ldhName", "").lower().rstrip(".")
            for ns in payload.get("nameservers", [])
            if isinstance(ns, dict) and ns.get("ldhName")
        ]
        registrar = None
        registrant_org = None
        country = payload.get("country")
        abuse_contacts: List[str] = []

        for entity in payload.get("entities", []):
            if not isinstance(entity, dict):
                continue
            roles = [r.lower() for r in entity.get("roles", [])]
            vcard = entity.get("vcardArray", [])
            org_name = self._extract_vcard_field(vcard, "fn") or self._extract_vcard_field(vcard, "org")
            email = self._extract_vcard_field(vcard, "email")
            if "registrar" in roles and org_name:
                registrar = org_name
            if "registrant" in roles and org_name:
                registrant_org = org_name
            if "abuse" in roles and email:
                abuse_contacts.append(email)
            for sub_ent in entity.get("entities", []):
                if isinstance(sub_ent, dict):
                    sub_roles = [r.lower() for r in sub_ent.get("roles", [])]
                    sub_email = self._extract_vcard_field(sub_ent.get("vcardArray", []), "email")
                    if "abuse" in sub_roles and sub_email:
                        abuse_contacts.append(sub_email)

        return {
            "source_protocol": "RDAP",
            "handle": payload.get("handle"),
            "ldh_name": payload.get("ldhName"),
            "created_at": events.get("registration"),
            "updated_at": events.get("last changed") or events.get("last update of RDAP database"),
            "expires_at": events.get("expiration"),
            "registrar": registrar or "NOT_DISCLOSED",
            "registrant_org": registrant_org or "REDACTED_OR_NOT_DISCLOSED",
            "country": country or "NOT_DISCLOSED",
            "nameservers": sorted(set(nameservers)),
            "statuses": payload.get("status", []),
            "abuse_contacts": sorted(set(abuse_contacts)),
        }

    @staticmethod
    def _extract_vcard_field(vcard: Any, target_field: str) -> Optional[str]:
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            return None
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and str(item[0]).lower() == target_field:
                val = item[3]
                if isinstance(val, str) and val.strip():
                    return val.strip()
        return None

    async def _whois_fallback(self, domain: str, timeout: float = 6.0) -> Optional[Dict[str, Any]]:
        try:
            clean_domain = validate_hostname_syntax(domain)
        except DomainSecurityError:
            return None

        def _sync_whois() -> Optional[str]:
            def _query_server(server: str, query_str: str) -> str:
                with socket.create_connection((server, 43), timeout=timeout) as sock:
                    sock.sendall((query_str + "\r\n").encode("utf-8"))
                    chunks: List[bytes] = []
                    while True:
                        buf = sock.recv(4096)
                        if not buf:
                            break
                        chunks.append(buf)
                        if sum(len(c) for c in chunks) > 128 * 1024:
                            break
                return b"".join(chunks).decode("utf-8", errors="ignore")

            iana_raw = _query_server("whois.iana.org", clean_domain)
            refer_server = None
            for line in iana_raw.splitlines():
                if line.lower().startswith("refer:"):
                    refer_server = line.split(":", 1)[1].strip()
                    break
            if not refer_server:
                return None
            return _query_server(refer_server, clean_domain)

        try:
            raw_text = await asyncio.to_thread(_sync_whois)
        except Exception:
            return None

        if not raw_text or "no match for" in raw_text.lower() or "not found" in raw_text.lower():
            return None

        created = updated = expires = registrar = registrant_org = country = None
        nameservers: List[str] = []
        statuses: List[str] = []
        abuse: List[str] = []

        for line in raw_text.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            kl = k.strip().lower()
            val = v.strip()
            if not val:
                continue
            if kl in ("creation date", "created", "created on") and not created:
                created = val
            elif kl in ("updated date", "last updated", "changed") and not updated:
                updated = val
            elif kl in ("registry expiry date", "expiration date", "expires on") and not expires:
                expires = val
            elif kl == "registrar" and not registrar:
                registrar = val
            elif kl in ("registrant organization", "org") and not registrant_org:
                registrant_org = val
            elif kl in ("registrant country", "country") and not country:
                country = val
            elif kl in ("name server", "nserver"):
                nameservers.append(val.lower().split()[0].rstrip("."))
            elif kl == "domain status":
                statuses.append(val.split()[0])
            elif kl in ("registrar abuse contact email", "abuse-mailbox"):
                abuse.append(val)

        return {
            "source_protocol": "WHOIS",
            "created_at": created,
            "updated_at": updated,
            "expires_at": expires,
            "registrar": registrar or "NOT_DISCLOSED",
            "registrant_org": registrant_org or "REDACTED_OR_NOT_DISCLOSED",
            "country": country or "NOT_DISCLOSED",
            "nameservers": sorted(set(nameservers)),
            "statuses": sorted(set(statuses)),
            "abuse_contacts": sorted(set(abuse)),
        }


class VirusTotalConnector:
    """
    Conector VirusTotal API v3 (solo lectura pasiva, nunca envía a escaneo público).
    """

    PROVIDER = "virustotal"

    async def query(
        self, target: str, input_type: IndicatorInputType, api_key: Optional[str], timeout: float = 10.0
    ) -> ProviderResponse:
        if not api_key:
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.KEY_NOT_CONFIGURED,
                error_message="API Key de VirusTotal no configurada.",
            )

        is_ip = input_type in (IndicatorInputType.IPV4, IndicatorInputType.IPV6)
        endpoint = (
            f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            if is_ip
            else f"https://www.virustotal.com/api/v3/domains/{target}"
        )
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        start = time.monotonic()

        try:
            resp = await safe_http_get(endpoint, headers=headers, timeout=timeout, max_redirects=0)
            latency = int((time.monotonic() - start) * 1000)

            if resp.status_code == 200:
                try:
                    payload = resp.json()
                    attrs = payload["data"]["attributes"]
                except (ValueError, KeyError, TypeError):
                    return ProviderResponse(
                        provider_name=self.PROVIDER,
                        status=ProviderQueryStatus.MALFORMED_RESPONSE,
                        error_message="Estructura JSON inesperada en VirusTotal.",
                        latency_ms=latency,
                    )

                stats = attrs.get("last_analysis_stats", {})
                last_date_ts = attrs.get("last_analysis_date")
                last_date_iso = (
                    datetime.utcfromtimestamp(last_date_ts).isoformat() + "Z"
                    if isinstance(last_date_ts, (int, float))
                    else None
                )
                return ProviderResponse(
                    provider_name=self.PROVIDER,
                    status=ProviderQueryStatus.SUCCESS,
                    latency_ms=latency,
                    data={
                        "reputation": attrs.get("reputation", 0),
                        "last_analysis_date": last_date_iso,
                        "stats": {
                            "harmless": stats.get("harmless", 0),
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "undetected": stats.get("undetected", 0),
                            "timeout": stats.get("timeout", 0),
                        },
                        "categories": attrs.get("categories", {}),
                        "asn": attrs.get("asn"),
                        "as_owner": attrs.get("as_owner"),
                        "country": attrs.get("country"),
                        "total_votes": attrs.get("total_votes", {}),
                    },
                )
            if resp.status_code in (401, 403):
                return ProviderResponse(
                    provider_name=self.PROVIDER,
                    status=ProviderQueryStatus.INVALID_KEY,
                    error_message="API Key de VirusTotal inválida o sin permisos.",
                    latency_ms=latency,
                )
            if resp.status_code == 404:
                return ProviderResponse(
                    provider_name=self.PROVIDER,
                    status=ProviderQueryStatus.NO_DATA,
                    error_message="Sin registros previos en VirusTotal.",
                    latency_ms=latency,
                )
            if resp.status_code == 429:
                return ProviderResponse(
                    provider_name=self.PROVIDER,
                    status=ProviderQueryStatus.RATE_LIMITED,
                    error_message="Cuota de VirusTotal alcanzada (HTTP 429).",
                    latency_ms=latency,
                )
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=f"VirusTotal HTTP {resp.status_code}",
                latency_ms=latency,
            )
        except httpx.TimeoutException:
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.TIMEOUT,
                error_message="Timeout consultando VirusTotal.",
                latency_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as exc:
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=f"Error de conexión con VirusTotal: {exc}",
                latency_ms=int((time.monotonic() - start) * 1000),
            )


class AlienVaultOTXConnector:
    """Conector real AlienVault OTX API v1 (Pulses, malware, passive DNS)."""

    PROVIDER = "otx"

    async def query(
        self, target: str, input_type: IndicatorInputType, api_key: Optional[str], timeout: float = 10.0
    ) -> ProviderResponse:
        if not api_key:
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.KEY_NOT_CONFIGURED,
                error_message="API Key de AlienVault OTX no configurada.",
            )

        if input_type == IndicatorInputType.IPV4:
            section_type = "IPv4"
        elif input_type == IndicatorInputType.IPV6:
            section_type = "IPv6"
        else:
            section_type = "domain"

        general_url = f"https://otx.alienvault.com/api/v1/indicators/{section_type}/{target}/general"
        headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
        start = time.monotonic()

        try:
            resp = await safe_http_get(general_url, headers=headers, timeout=timeout, max_redirects=0)
            latency = int((time.monotonic() - start) * 1000)

            if resp.status_code == 200:
                try:
                    payload = resp.json()
                    pulse_info = payload.get("pulse_info", {})
                    pulses_raw = pulse_info.get("pulses", [])
                except (ValueError, AttributeError, TypeError):
                    return ProviderResponse(
                        provider_name=self.PROVIDER,
                        status=ProviderQueryStatus.MALFORMED_RESPONSE,
                        error_message="Respuesta OTX malformada.",
                        latency_ms=latency,
                    )

                pulses = []
                malware_families: Set[str] = set()
                tags: Set[str] = set()

                for p in pulses_raw[:25]:
                    if not isinstance(p, dict):
                        continue
                    p_tags = [str(t) for t in p.get("tags", []) if t]
                    p_malware = [
                        m.get("display_name") or m.get("id")
                        for m in p.get("malware_families", [])
                        if isinstance(m, dict) and (m.get("display_name") or m.get("id"))
                    ]
                    tags.update(p_tags)
                    malware_families.update(p_malware)
                    pulses.append({
                        "id": p.get("id"),
                        "name": p.get("name"),
                        "description": (p.get("description") or "")[:400],
                        "created": p.get("created"),
                        "modified": p.get("modified"),
                        "tags": p_tags,
                        "malware_families": p_malware,
                        "adversary": p.get("adversary") or None,
                        "references": p.get("references", [])[:5],
                    })

                return ProviderResponse(
                    provider_name=self.PROVIDER,
                    status=ProviderQueryStatus.SUCCESS,
                    latency_ms=latency,
                    data={
                        "pulse_count": pulse_info.get("count", len(pulses)),
                        "pulses": pulses,
                        "malware_families": sorted(malware_families),
                        "tags": sorted(tags),
                        "asn": payload.get("asn"),
                        "country_name": payload.get("country_name"),
                    },
                )
            if resp.status_code in (401, 403):
                return ProviderResponse(
                    provider_name=self.PROVIDER,
                    status=ProviderQueryStatus.INVALID_KEY,
                    error_message="API Key de AlienVault OTX inválida.",
                    latency_ms=latency,
                )
            if resp.status_code == 404:
                return ProviderResponse(
                    provider_name=self.PROVIDER,
                    status=ProviderQueryStatus.NO_DATA,
                    error_message="Sin información en AlienVault OTX.",
                    latency_ms=latency,
                )
            if resp.status_code == 429:
                return ProviderResponse(
                    provider_name=self.PROVIDER,
                    status=ProviderQueryStatus.RATE_LIMITED,
                    error_message="Límite de solicitudes alcanzado en OTX.",
                    latency_ms=latency,
                )
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=f"OTX HTTP {resp.status_code}",
                latency_ms=latency,
            )
        except httpx.TimeoutException:
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.TIMEOUT,
                error_message="Timeout consultando AlienVault OTX.",
                latency_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as exc:
            return ProviderResponse(
                provider_name=self.PROVIDER,
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=f"Error de conexión con OTX: {exc}",
                latency_ms=int((time.monotonic() - start) * 1000),
            )


class DNSAndCTConnector:
    """Consulta registros DNS (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR) y Certificate Transparency (crt.sh)."""

    PROVIDER_DNS = "dns"
    PROVIDER_CT = "crt_sh"

    async def query_dns(self, target: str, input_type: IndicatorInputType, timeout: float = 5.0) -> ProviderResponse:
        start = time.monotonic()

        def _resolve_sync() -> Dict[str, Any]:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

            records: Dict[str, List[Any]] = {
                "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": [], "PTR": []
            }

            if input_type in (IndicatorInputType.IPV4, IndicatorInputType.IPV6):
                try:
                    rev = dns.reversename.from_address(target)
                    ans = resolver.resolve(rev, "PTR")
                    records["PTR"] = [str(r.target).rstrip(".") for r in ans]
                except Exception:
                    pass
                return records

            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
                try:
                    ans = resolver.resolve(target, rtype)
                    for r in ans:
                        if rtype == "MX":
                            records["MX"].append({"preference": r.preference, "host": str(r.exchange).rstrip(".")})
                        elif rtype == "TXT":
                            txt_val = "".join(
                                s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                                for s in r.strings
                            )
                            records["TXT"].append(txt_val)
                        elif rtype == "SOA":
                            records["SOA"].append({
                                "mname": str(r.mname).rstrip("."),
                                "rname": str(r.rname).rstrip("."),
                                "serial": r.serial,
                            })
                        else:
                            records[rtype].append(r.to_text().rstrip("."))
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                    continue
                except Exception:
                    continue

            # PTR para la primera IP A resuelta
            if records["A"]:
                try:
                    rev = dns.reversename.from_address(records["A"][0])
                    ptr_ans = resolver.resolve(rev, "PTR")
                    records["PTR"] = [str(r.target).rstrip(".") for r in ptr_ans]
                except Exception:
                    pass

            return records

        try:
            records = await asyncio.to_thread(_resolve_sync)
            latency = int((time.monotonic() - start) * 1000)
            has_any = any(len(v) > 0 for v in records.values())
            return ProviderResponse(
                provider_name=self.PROVIDER_DNS,
                status=ProviderQueryStatus.SUCCESS if has_any else ProviderQueryStatus.NO_DATA,
                data=records,
                latency_ms=latency,
            )
        except Exception as exc:
            return ProviderResponse(
                provider_name=self.PROVIDER_DNS,
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=f"Error DNS: {exc}",
                latency_ms=int((time.monotonic() - start) * 1000),
            )

    async def query_ct(self, domain: str, input_type: IndicatorInputType, timeout: float = 12.0) -> ProviderResponse:
        if input_type in (IndicatorInputType.IPV4, IndicatorInputType.IPV6):
            return ProviderResponse(
                provider_name=self.PROVIDER_CT,
                status=ProviderQueryStatus.NO_DATA,
                data={"certificates": [], "subdomains": []},
            )

        url = f"https://crt.sh/?q=%.{domain}&output=json"
        start = time.monotonic()
        try:
            resp = await safe_http_get(url, headers={"Accept": "application/json"}, timeout=timeout, max_redirects=1)
            latency = int((time.monotonic() - start) * 1000)

            if resp.status_code == 200:
                try:
                    entries = resp.json()
                    if not isinstance(entries, list):
                        raise ValueError("Not a list")
                except ValueError:
                    return ProviderResponse(
                        provider_name=self.PROVIDER_CT,
                        status=ProviderQueryStatus.MALFORMED_RESPONSE,
                        error_message="Respuesta de crt.sh no válida.",
                        latency_ms=latency,
                    )

                subdomains: Set[str] = set()
                certs: List[Dict[str, Any]] = []
                seen_cert_ids: Set[Any] = set()

                for entry in entries[:150]:
                    if not isinstance(entry, dict):
                        continue
                    name_val = entry.get("name_value", "")
                    for sub in str(name_val).splitlines():
                        s = sub.strip().lower().lstrip("*.")
                        if s and domain in s and "@" not in s and " " not in s:
                            subdomains.add(s)

                    cid = entry.get("id")
                    if cid and cid not in seen_cert_ids and len(certs) < 30:
                        seen_cert_ids.add(cid)
                        certs.append({
                            "id": cid,
                            "common_name": entry.get("common_name"),
                            "issuer_name": entry.get("issuer_name"),
                            "not_before": entry.get("not_before"),
                            "not_after": entry.get("not_after"),
                        })

                return ProviderResponse(
                    provider_name=self.PROVIDER_CT,
                    status=ProviderQueryStatus.SUCCESS if (certs or subdomains) else ProviderQueryStatus.NO_DATA,
                    latency_ms=latency,
                    data={
                        "certificates_count": len(certs),
                        "certificates": certs,
                        "subdomains": sorted(subdomains),
                    },
                )
            if resp.status_code == 429:
                return ProviderResponse(
                    provider_name=self.PROVIDER_CT,
                    status=ProviderQueryStatus.RATE_LIMITED,
                    error_message="crt.sh alcanzó límite de peticiones.",
                    latency_ms=latency,
                )
            return ProviderResponse(
                provider_name=self.PROVIDER_CT,
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=f"crt.sh HTTP {resp.status_code}",
                latency_ms=latency,
            )
        except httpx.TimeoutException:
            return ProviderResponse(
                provider_name=self.PROVIDER_CT,
                status=ProviderQueryStatus.TIMEOUT,
                error_message="Timeout consultando crt.sh.",
                latency_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as exc:
            return ProviderResponse(
                provider_name=self.PROVIDER_CT,
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=f"Error crt.sh: {exc}",
                latency_ms=int((time.monotonic() - start) * 1000),
            )


class ComplementaryCTIConnector:
    """Reutiliza los adaptadores existentes (AbuseIPDB, URLhaus, ThreatFox) con estado normalizado."""

    def __init__(self) -> None:
        self.abuseipdb = AbuseIPDBAdapter()
        self.urlhaus = URLhausAdapter()
        self.threatfox = ThreatFoxAdapter()

    async def query_urlhaus(self, domain: str, api_key: Optional[str] = None) -> ProviderResponse:
        start = time.monotonic()
        res = await self.urlhaus.query_domain(domain, api_key=api_key)
        latency = int((time.monotonic() - start) * 1000)
        if not res.get("available"):
            return ProviderResponse(
                provider_name="urlhaus",
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=res.get("error", "URLhaus no disponible."),
                latency_ms=latency,
            )
        if res.get("status") == "NOT_FOUND":
            return ProviderResponse(
                provider_name="urlhaus",
                status=ProviderQueryStatus.NO_DATA,
                data=res,
                latency_ms=latency,
            )
        return ProviderResponse(
            provider_name="urlhaus",
            status=ProviderQueryStatus.SUCCESS,
            data=res,
            latency_ms=latency,
        )

    async def query_abuseipdb(self, ip_address: Optional[str], api_key: Optional[str]) -> ProviderResponse:
        if not api_key:
            return ProviderResponse(
                provider_name="abuseipdb",
                status=ProviderQueryStatus.KEY_NOT_CONFIGURED,
                error_message="API Key de AbuseIPDB no configurada.",
            )
        if not ip_address:
            return ProviderResponse(
                provider_name="abuseipdb",
                status=ProviderQueryStatus.NO_DATA,
                error_message="No hay IP resuelta para consultar en AbuseIPDB.",
            )
        start = time.monotonic()
        res = await self.abuseipdb.query_ip(ip_address, api_key=api_key)
        latency = int((time.monotonic() - start) * 1000)
        if not res.get("available"):
            return ProviderResponse(
                provider_name="abuseipdb",
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=res.get("error") or res.get("reason") or "AbuseIPDB falló.",
                latency_ms=latency,
            )
        return ProviderResponse(
            provider_name="abuseipdb",
            status=ProviderQueryStatus.SUCCESS,
            data=res,
            latency_ms=latency,
        )

    async def query_threatfox(self, indicator: str, api_key: Optional[str] = None) -> ProviderResponse:
        start = time.monotonic()
        res = await self.threatfox.query_ip(indicator, api_key=api_key)
        latency = int((time.monotonic() - start) * 1000)
        if not res.get("available"):
            return ProviderResponse(
                provider_name="threatfox",
                status=ProviderQueryStatus.CONNECTION_ERROR,
                error_message=res.get("error", "ThreatFox no disponible."),
                latency_ms=latency,
            )
        if res.get("matches_count", 0) == 0:
            return ProviderResponse(
                provider_name="threatfox",
                status=ProviderQueryStatus.NO_DATA,
                data=res,
                latency_ms=latency,
            )
        return ProviderResponse(
            provider_name="threatfox",
            status=ProviderQueryStatus.SUCCESS,
            data=res,
            latency_ms=latency,
        )
