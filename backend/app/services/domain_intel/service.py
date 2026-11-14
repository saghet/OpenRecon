import asyncio
import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.domain_security import (
    CredentialVault,
    DomainSecurityError,
    enforce_anti_ssrf_and_dns_rebinding,
    validate_and_normalize_indicator,
)
from app.models.asset import Asset
from app.models.domain_intel import (
    DomainIndicator,
    DomainInvestigation,
    DomainProviderResult,
    DomainReputationHistory,
    DomainRiskTier,
    IndicatorInputType,
    ProviderCredential,
    ProviderQueryStatus,
)
from app.models.organization import Organization, Seed
from app.services.domain_intel.base import AsyncRateLimiter, ProviderResponse
from app.services.domain_intel.connectors import (
    AlienVaultOTXConnector,
    ComplementaryCTIConnector,
    DNSAndCTConnector,
    RDAPWhoisConnector,
    VirusTotalConnector,
)
from app.services.domain_intel.risk_and_correlation import (
    assess_domain_risk,
    build_domain_correlation_graph,
)

SUPPORTED_PROVIDERS = [
    "rdap_whois",
    "virustotal",
    "otx",
    "dns",
    "crt_sh",
    "urlhaus",
    "threatfox",
    "abuseipdb",
]


class DomainIntelligenceService:
    """Servicio central de investigación de dominios, IPs y URLs integrado con OpenRecon."""

    _rate_limiter = AsyncRateLimiter(min_interval_seconds=0.2)

    def __init__(self, db: Session):
        self.db = db
        self.rdap = RDAPWhoisConnector()
        self.vt = VirusTotalConnector()
        self.otx = AlienVaultOTXConnector()
        self.dns_ct = DNSAndCTConnector()
        self.cti = ComplementaryCTIConnector()

    def _get_provider_keys(self, organization_id: int) -> Dict[str, Optional[str]]:
        keys: Dict[str, Optional[str]] = {
            "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
            "otx": os.getenv("OTX_API_KEY"),
            "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
            "urlhaus": os.getenv("URLHAUS_API_KEY"),
            "threatfox": os.getenv("THREATFOX_API_KEY"),
        }
        creds = (
            self.db.query(ProviderCredential)
            .filter(ProviderCredential.organization_id == organization_id, ProviderCredential.is_enabled == True)
            .all()
        )
        for cred in creds:
            try:
                keys[cred.provider_name] = CredentialVault.decrypt_key(cred.encrypted_api_key)
            except DomainSecurityError:
                continue
        return keys

    async def investigate(
        self,
        organization_id: int,
        target: str,
        use_cache: bool = True,
        cache_ttl_seconds: int = 3600,
        enabled_providers: Optional[List[str]] = None,
        enforce_roe_scope: bool = False,
        authorized_scope: Optional[List[str]] = None,
        trigger_source: str = "MANUAL",
        asset_id: Optional[int] = None,
    ) -> DomainInvestigation:
        org = self.db.query(Organization).filter(Organization.id == organization_id).first()
        if not org:
            if organization_id == 1:
                org = Organization(id=1, name="OpenRecon Default Organization", description="Auto-initialized default organization")
                self.db.add(org)
                self.db.commit()
                self.db.refresh(org)
            else:
                raise DomainSecurityError(f"Organización {organization_id} no encontrada.")

        norm = validate_and_normalize_indicator(target)
        normalized_domain = norm["normalized_domain"]
        input_type: IndicatorInputType = norm["input_type"]

        scope_list: Optional[List[str]] = None
        if enforce_roe_scope:
            if authorized_scope is not None:
                scope_list = [s.strip().lower() for s in authorized_scope if s and s.strip()]
            else:
                seeds = self.db.query(Seed).filter(Seed.organization_id == organization_id, Seed.is_active == 1).all()
                scope_list = [s.value for s in seeds]
            if not scope_list:
                raise DomainSecurityError("No hay semillas autorizadas configuradas para investigar (RoE).")

        enforce_anti_ssrf_and_dns_rebinding(normalized_domain, authorized_scope=scope_list, resolve_dns=True)

        # 1. Verificar caché vigente
        if use_cache:
            now = datetime.utcnow()
            cached = (
                self.db.query(DomainInvestigation)
                .filter(
                    DomainInvestigation.organization_id == organization_id,
                    DomainInvestigation.normalized_domain == normalized_domain,
                    DomainInvestigation.status == "COMPLETED",
                    DomainInvestigation.cache_expires_at != None,
                    DomainInvestigation.cache_expires_at > now,
                )
                .order_by(DomainInvestigation.created_at.desc())
                .first()
            )
            if cached:
                return cached

        # 2. Enlazar con activo existente si no se pasó asset_id
        if asset_id is None:
            matched_asset = (
                self.db.query(Asset)
                .filter(Asset.organization_id == organization_id, Asset.value == normalized_domain)
                .first()
            )
            if matched_asset:
                asset_id = matched_asset.id

        investigation = DomainInvestigation(
            organization_id=organization_id,
            asset_id=asset_id,
            target_input=norm["raw_input"],
            normalized_domain=normalized_domain,
            input_type=input_type,
            trigger_source=trigger_source,
            status="RUNNING",
        )
        self.db.add(investigation)
        self.db.commit()
        self.db.refresh(investigation)

        active_set = set(enabled_providers) if enabled_providers else set(SUPPORTED_PROVIDERS)
        keys = self._get_provider_keys(organization_id)

        # 3. Ejecutar consultas independientes en paralelo
        tasks: Dict[str, Any] = {}
        if "rdap_whois" in active_set:
            tasks["rdap_whois"] = self._run_limited("rdap_whois", self.rdap.query(normalized_domain, input_type))
        if "virustotal" in active_set:
            tasks["virustotal"] = self._run_limited(
                "virustotal", self.vt.query(normalized_domain, input_type, keys.get("virustotal"))
            )
        if "otx" in active_set:
            tasks["otx"] = self._run_limited("otx", self.otx.query(normalized_domain, input_type, keys.get("otx")))
        if "dns" in active_set:
            tasks["dns"] = self._run_limited("dns", self.dns_ct.query_dns(normalized_domain, input_type))
        if "crt_sh" in active_set:
            tasks["crt_sh"] = self._run_limited("crt_sh", self.dns_ct.query_ct(normalized_domain, input_type))
        if "urlhaus" in active_set:
            tasks["urlhaus"] = self._run_limited("urlhaus", self.cti.query_urlhaus(normalized_domain, keys.get("urlhaus")))
        if "threatfox" in active_set:
            tasks["threatfox"] = self._run_limited("threatfox", self.cti.query_threatfox(normalized_domain, keys.get("threatfox")))

        keys_order = list(tasks.keys())
        responses_list = await asyncio.gather(*tasks.values(), return_exceptions=True)

        provider_results: Dict[str, ProviderResponse] = {}
        for pname, resp in zip(keys_order, responses_list):
            if isinstance(resp, Exception):
                provider_results[pname] = ProviderResponse(
                    provider_name=pname,
                    status=ProviderQueryStatus.CONNECTION_ERROR,
                    error_message=str(resp),
                )
            else:
                provider_results[pname] = resp

        # AbuseIPDB sobre la IP directa o primera IP A resuelta
        if "abuseipdb" in active_set:
            target_ip = normalized_domain if input_type in (IndicatorInputType.IPV4, IndicatorInputType.IPV6) else None
            if not target_ip and "dns" in provider_results and provider_results["dns"].status == ProviderQueryStatus.SUCCESS:
                a_recs = provider_results["dns"].data.get("A", [])
                if a_recs:
                    target_ip = a_recs[0]
            provider_results["abuseipdb"] = await self._run_limited(
                "abuseipdb", self.cti.query_abuseipdb(target_ip, keys.get("abuseipdb"))
            )

        # 4. Correlación y Risk Assessment explicable
        graph_data, indicators = build_domain_correlation_graph(normalized_domain, provider_results)
        risk_eval = assess_domain_risk(provider_results, asset_technical_score=None)

        # 5. Persistir resultados por proveedor e indicadores
        for pname, pres in provider_results.items():
            self.db.add(
                DomainProviderResult(
                    investigation_id=investigation.id,
                    provider_name=pname,
                    status=pres.status,
                    from_cache=pres.from_cache,
                    latency_ms=pres.latency_ms,
                    queried_at=pres.queried_at,
                    error_message=pres.error_message,
                    data_json=json.dumps(pres.data, default=str),
                )
            )

        for ind in indicators:
            self.db.add(
                DomainIndicator(
                    investigation_id=investigation.id,
                    indicator_type=ind["indicator_type"],
                    indicator_value=ind["indicator_value"],
                    source=ind["source"],
                    relationship_type=ind["relationship_type"],
                    confidence=ind["confidence"],
                    evidence=ind["evidence"],
                )
            )

        vt_stats = (provider_results.get("virustotal").data.get("stats", {}) if provider_results.get("virustotal") else {})
        otx_count = (provider_results.get("otx").data.get("pulse_count") if provider_results.get("otx") else None)

        self.db.add(
            DomainReputationHistory(
                organization_id=organization_id,
                investigation_id=investigation.id,
                normalized_domain=normalized_domain,
                risk_tier=risk_eval["risk_tier"],
                external_reputation_score=risk_eval["external_reputation_score"],
                vt_malicious=vt_stats.get("malicious"),
                vt_suspicious=vt_stats.get("suspicious"),
                otx_pulses=otx_count,
            )
        )

        summary_payload = {
            "positive_evidences": risk_eval["positive_evidences"],
            "negative_evidences": risk_eval["negative_evidences"],
            "sources_consulted": risk_eval["sources_consulted"],
            "indicators_count": len(indicators),
        }

        investigation.status = "COMPLETED"
        investigation.risk_tier = risk_eval["risk_tier"]
        investigation.technical_risk_score = risk_eval["technical_risk_score"]
        investigation.external_reputation_score = risk_eval["external_reputation_score"]
        investigation.confidence_score = risk_eval["confidence_score"]
        investigation.risk_explanation = risk_eval["explanation"]
        investigation.summary_json = json.dumps(summary_payload, default=str)
        investigation.correlation_graph_json = json.dumps(graph_data, default=str)
        investigation.limitations_json = json.dumps(risk_eval["limitations"], default=str)
        investigation.cache_expires_at = datetime.utcnow() + timedelta(seconds=cache_ttl_seconds)
        investigation.completed_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(investigation)
        return investigation

    async def _run_limited(self, provider_name: str, coro: Any) -> ProviderResponse:
        await self._rate_limiter.wait(provider_name)
        return await coro
