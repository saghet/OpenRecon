from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.models.domain_intel import DomainRiskTier, ProviderQueryStatus, RelationshipConfidenceType
from app.services.correlation.graph_engine import CorrelationGraphEngine
from app.services.domain_intel.base import ProviderResponse


def build_domain_correlation_graph(
    target_domain: str,
    provider_results: Dict[str, ProviderResponse],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Construye el grafo de correlación usando CorrelationGraphEngine y extrae
    la lista estructurada de indicadores con procedencia y nivel de confianza.
    """
    graph = CorrelationGraphEngine()
    root_id = f"domain_{target_domain}"
    graph.add_node(root_id, target_domain, "DOMAIN", {"root": True})
    indicators: List[Dict[str, Any]] = []

    def _register(
        ind_type: str,
        value: str,
        source: str,
        rel_name: str,
        rel_type: RelationshipConfidenceType,
        confidence: int,
        evidence: str,
        node_type: Optional[str] = None,
    ) -> None:
        if not value:
            return
        nid = f"{(node_type or ind_type).lower()}_{value}"
        graph.add_node(nid, value, node_type or ind_type, {"source": source, "relationship_type": rel_type.value})
        graph.add_edge(root_id, nid, rel_name, confidence=confidence, evidence=f"[{source} | {rel_type.value}] {evidence}")
        indicators.append({
            "indicator_type": ind_type,
            "indicator_value": value,
            "source": source,
            "relationship_type": rel_type,
            "confidence": confidence,
            "evidence": evidence,
        })

    # 1. DNS
    dns_res = provider_results.get("dns")
    if dns_res and dns_res.status == ProviderQueryStatus.SUCCESS:
        for ip in dns_res.data.get("A", []) + dns_res.data.get("AAAA", []):
            _register("IP", ip, "dns", "RESOLVES_TO", RelationshipConfidenceType.CONFIRMED, 95, f"Registro DNS A/AAAA para {target_domain}")
        for ns in dns_res.data.get("NS", []):
            _register("NAMESERVER", ns, "dns", "USES_NS", RelationshipConfidenceType.CONFIRMED, 95, "Registro DNS NS autoritativo")
        for mx in dns_res.data.get("MX", []):
            host = mx.get("host") if isinstance(mx, dict) else str(mx)
            _register("MX", host, "dns", "USES_MX", RelationshipConfidenceType.CONFIRMED, 95, "Registro DNS MX")

    # 2. RDAP / WHOIS
    rdap_res = provider_results.get("rdap_whois")
    if rdap_res and rdap_res.status == ProviderQueryStatus.SUCCESS:
        for ns in rdap_res.data.get("nameservers", []):
            _register("NAMESERVER", ns, "rdap_whois", "REGISTERED_NS", RelationshipConfidenceType.CONFIRMED, 90, "Nameserver declarado en RDAP/WHOIS")

    # 3. Certificate Transparency (crt.sh)
    ct_res = provider_results.get("crt_sh")
    if ct_res and ct_res.status == ProviderQueryStatus.SUCCESS:
        for sub in ct_res.data.get("subdomains", [])[:25]:
            if sub != target_domain:
                _register("SUBDOMAIN", sub, "crt_sh", "HAS_CERT_SAN", RelationshipConfidenceType.OBSERVED, 80, "Subdominio observado en logs CT (crt.sh)")
        for cert in ct_res.data.get("certificates", [])[:10]:
            cname = cert.get("common_name") or str(cert.get("id"))
            _register("CERT", f"crt:{cert.get('id')} ({cname})", "crt_sh", "ISSUED_CERT", RelationshipConfidenceType.OBSERVED, 85, f"Emisor: {cert.get('issuer_name')}")

    # 4. VirusTotal
    vt_res = provider_results.get("virustotal")
    if vt_res and vt_res.status == ProviderQueryStatus.SUCCESS:
        asn = vt_res.data.get("asn")
        if asn:
            _register("ASN", f"AS{asn} ({vt_res.data.get('as_owner', 'Unknown')})", "virustotal", "BELONGS_TO_ASN", RelationshipConfidenceType.OBSERVED, 85, "ASN reportado por VirusTotal")

    # 5. AlienVault OTX
    otx_res = provider_results.get("otx")
    if otx_res and otx_res.status == ProviderQueryStatus.SUCCESS:
        for mal in otx_res.data.get("malware_families", [])[:15]:
            _register("MALWARE", mal, "otx", "ASSOCIATED_MALWARE", RelationshipConfidenceType.OBSERVED, 75, "Familia de malware asociada en OTX Pulse")
        for pulse in otx_res.data.get("pulses", [])[:10]:
            pname = pulse.get("name") or pulse.get("id")
            _register("PULSE", str(pname), "otx", "MENTIONED_IN_PULSE", RelationshipConfidenceType.OBSERVED, 70, f"Pulse OTX ID {pulse.get('id')}")
            if pulse.get("adversary"):
                _register(
                    "THREAT_ACTOR",
                    str(pulse["adversary"]),
                    "otx",
                    "ATTRIBUTED_IN_PULSE",
                    RelationshipConfidenceType.INFERRED,
                    45,
                    "Adversario documentado en Pulse OTX (requiere corroboración adicional)",
                )

    # 6. URLhaus & ThreatFox
    uh_res = provider_results.get("urlhaus")
    if uh_res and uh_res.status == ProviderQueryStatus.SUCCESS and uh_res.data.get("malicious_urls_count", 0) > 0:
        _register("URL", f"{uh_res.data['malicious_urls_count']} URLs en URLhaus", "urlhaus", "HOSTS_MALWARE_URL", RelationshipConfidenceType.CONFIRMED, 90, f"Amenaza: {uh_res.data.get('threat')}")

    tf_res = provider_results.get("threatfox")
    if tf_res and tf_res.status == ProviderQueryStatus.SUCCESS and tf_res.data.get("matches_count", 0) > 0:
        mal = tf_res.data.get("malware_printable") or tf_res.data.get("threat_type") or "IoC"
        _register("MALWARE", str(mal), "threatfox", "THREATFOX_IOC", RelationshipConfidenceType.CONFIRMED, int(tf_res.data.get("confidence_level") or 75), "Coincidencia directa en ThreatFox")

    return {"nodes": list(graph.nodes.values()), "edges": graph.edges}, indicators


def assess_domain_risk(
    provider_results: Dict[str, ProviderResponse],
    asset_technical_score: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Evaluación de riesgo explicable para dominios/IPs/URLs.
    Separa riesgo técnico, reputación externa y nivel de confianza.
    """
    negative_evidences: List[Dict[str, str]] = []
    positive_evidences: List[Dict[str, str]] = []
    limitations: List[str] = []
    sources_consulted: List[str] = []

    external_points = 0.0
    available_sources = 0
    total_sources = len(provider_results)

    for name, res in provider_results.items():
        sources_consulted.append(f"{name}:{res.status.value}")
        if res.status == ProviderQueryStatus.SUCCESS:
            available_sources += 1
        elif res.status in (
            ProviderQueryStatus.KEY_NOT_CONFIGURED,
            ProviderQueryStatus.INVALID_KEY,
            ProviderQueryStatus.TIMEOUT,
            ProviderQueryStatus.CONNECTION_ERROR,
            ProviderQueryStatus.RATE_LIMITED,
        ):
            limitations.append(f"{name}: {res.status.value} ({res.error_message or 'sin detalle'})")

    # 1. VirusTotal
    vt = provider_results.get("virustotal")
    if vt and vt.status == ProviderQueryStatus.SUCCESS:
        stats = vt.data.get("stats", {})
        mal = int(stats.get("malicious", 0))
        susp = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        if mal >= 5:
            external_points += 55.0
            negative_evidences.append({"source": "virustotal", "detail": f"{mal} motores reportan actividad maliciosa y {susp} sospechosa."})
        elif mal >= 1 or susp >= 2:
            external_points += 30.0
            negative_evidences.append({"source": "virustotal", "detail": f"{mal} detecciones maliciosas y {susp} sospechosas."})
        elif harmless > 0:
            positive_evidences.append({"source": "virustotal", "detail": f"0 detecciones maliciosas ({harmless} inofensivos); esto NO garantiza seguridad absoluta."})

    # 2. URLhaus / ThreatFox / AbuseIPDB
    uh = provider_results.get("urlhaus")
    if uh and uh.status == ProviderQueryStatus.SUCCESS and uh.data.get("malicious_urls_count", 0) > 0:
        external_points += 35.0
        negative_evidences.append({"source": "urlhaus", "detail": f"{uh.data['malicious_urls_count']} URLs asociadas a distribución de malware."})

    tf = provider_results.get("threatfox")
    if tf and tf.status == ProviderQueryStatus.SUCCESS and tf.data.get("matches_count", 0) > 0:
        external_points += 35.0
        negative_evidences.append({"source": "threatfox", "detail": f"IoC activo en ThreatFox ({tf.data.get('malware_printable')})."})

    ab = provider_results.get("abuseipdb")
    if ab and ab.status == ProviderQueryStatus.SUCCESS:
        score = int(ab.data.get("abuse_confidence_score", 0))
        if score >= 50:
            external_points += 30.0
            negative_evidences.append({"source": "abuseipdb", "detail": f"Confianza de abuso IP: {score}% ({ab.data.get('total_reports', 0)} reportes)."})
        elif score > 0:
            external_points += 10.0
            negative_evidences.append({"source": "abuseipdb", "detail": f"Reportes menores en AbuseIPDB ({score}%)."})

    # 3. AlienVault OTX (no confundir cantidad de pulses con peligrosidad directa)
    otx = provider_results.get("otx")
    if otx and otx.status == ProviderQueryStatus.SUCCESS:
        pcount = int(otx.data.get("pulse_count", 0))
        malfam = otx.data.get("malware_families", [])
        if malfam:
            external_points += 25.0
            negative_evidences.append({"source": "otx", "detail": f"Asociado a familias de malware en OTX: {', '.join(malfam[:5])}."})
        elif pcount > 0:
            external_points += 10.0
            negative_evidences.append({"source": "otx", "detail": f"Mencionado en {pcount} Pulses OTX (requiere revisión de contexto, el conteo por sí solo no implica compromiso)."})

    # 4. RDAP / WHOIS (antigüedad NO es prueba de legitimidad; dominio muy reciente + señales sí suma contexto)
    rdap = provider_results.get("rdap_whois")
    if rdap and rdap.status == ProviderQueryStatus.SUCCESS:
        created = rdap.data.get("created_at")
        if created:
            try:
                dt = datetime.fromisoformat(str(created).replace("Z", "+00:00")).replace(tzinfo=None)
                age_days = (datetime.utcnow() - dt).days
                if age_days < 30:
                    external_points += 10.0
                    negative_evidences.append({"source": "rdap_whois", "detail": f"Dominio recién registrado ({age_days} días)."})
            except Exception:
                pass

    confidence_score = round(available_sources / max(1, total_sources), 2)
    external_reputation_score = min(100.0, round(external_points, 1)) if available_sources > 0 else None

    if available_sources == 0:
        tier = DomainRiskTier.UNKNOWN
        explanation = "No se obtuvo respuesta válida de ninguna fuente de inteligencia externa."
    elif external_reputation_score >= 80.0:
        tier = DomainRiskTier.CRITICAL
        explanation = "Múltiples fuentes independientes reportan actividad maliciosa o IoCs activos."
    elif external_reputation_score >= 55.0:
        tier = DomainRiskTier.HIGH
        explanation = "Evidencia relevante de actividad maliciosa o abuso en proveedores externos."
    elif external_reputation_score >= 25.0:
        tier = DomainRiskTier.MEDIUM
        explanation = "Indicadores sospechosos o detecciones parciales que requieren análisis del analista."
    elif external_reputation_score > 0.0:
        tier = DomainRiskTier.LOW
        explanation = "Señales menores observadas sin evidencia concluyente de compromiso."
    else:
        tier = DomainRiskTier.INFORMATIONAL
        explanation = "Sin detecciones maliciosas en las fuentes disponibles (la ausencia de detecciones no garantiza seguridad)."

    return {
        "risk_tier": tier,
        "technical_risk_score": asset_technical_score,
        "external_reputation_score": external_reputation_score,
        "confidence_score": confidence_score,
        "explanation": explanation,
        "positive_evidences": positive_evidences,
        "negative_evidences": negative_evidences,
        "limitations": limitations,
        "sources_consulted": sources_consulted,
    }
