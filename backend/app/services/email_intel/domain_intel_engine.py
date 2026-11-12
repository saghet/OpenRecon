"""
Email Domain & DNS Security Intelligence Engine.
Performs passive DNS queries to inspect email infrastructure posture:
- MX records (priority & host)
- Mail Provider Identification (Google Workspace, Microsoft 365, Proofpoint, Mimecast, Proton, Zoho, etc.)
- SPF Record validation (RFC 7208)
- DMARC Policy verification (RFC 7489)
- DKIM common selector inspection (default, google, s1, selector1, k1)
- Security scoring and remediation recommendations.
"""

import dns.resolver
import logging
from typing import Dict, Any, List

logger = logging.getLogger("email_intel.domain_engine")

COMMON_DKIM_SELECTORS = ["default", "google", "s1", "s2", "selector1", "k1", "protonmail"]


class DomainIntelEngine:
    def __init__(self, timeout: float = 4.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Executes complete DNS posture analysis for an email domain.
        """
        clean_domain = domain.strip().lower()
        result = {
            "domain": clean_domain,
            "mail_provider": "Unknown / Self-Hosted",
            "mx_records": [],
            "spf_record": None,
            "spf_status": "MISSING",
            "dmarc_record": None,
            "dmarc_status": "MISSING",
            "dkim_status": "NOT_TESTED",
            "dns_security_score": 100,
            "weaknesses": [],
            "recommendations": []
        }

        # 1. MX Records Analysis
        try:
            answers = self.resolver.resolve(clean_domain, "MX")
            for rdata in answers:
                exchange = str(rdata.exchange).rstrip(".")
                result["mx_records"].append({
                    "preference": rdata.preference,
                    "host": exchange
                })
            # Sort by priority
            result["mx_records"].sort(key=lambda x: x["preference"])

            # Identify provider
            all_mx = " ".join([m["host"].lower() for m in result["mx_records"]])
            if "google" in all_mx or "googlemail" in all_mx or "aspmx" in all_mx:
                result["mail_provider"] = "Google Workspace (Gmail Enterprise)"
            elif "outlook" in all_mx or "microsoft" in all_mx or "pphosted" in all_mx:
                result["mail_provider"] = "Microsoft 365 / Exchange Online"
            elif "proton" in all_mx:
                result["mail_provider"] = "Proton Mail Enterprise"
            elif "mimecast" in all_mx:
                result["mail_provider"] = "Mimecast Secure Email Gateway"
            elif "proofpoint" in all_mx:
                result["mail_provider"] = "Proofpoint Protection Server"
            elif "zoho" in all_mx:
                result["mail_provider"] = "Zoho Mail"
            elif "ovh" in all_mx:
                result["mail_provider"] = "OVHcloud Mail"
            elif len(result["mx_records"]) > 0:
                result["mail_provider"] = f"Custom / Private Relay ({result['mx_records'][0]['host']})"
            else:
                result["mail_provider"] = "No MX Found"
                result["dns_security_score"] -= 40
                result["weaknesses"].append("Dominio sin servidores MX configurados (no puede recibir correo legítimo).")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            result["mail_provider"] = "No MX Resolved"
            result["dns_security_score"] -= 40
            result["weaknesses"].append("Fallo en resolución de registros MX o dominio inexistente.")
        except Exception as e:
            result["mail_provider"] = f"Error: {str(e)}"
            result["weaknesses"].append(f"Error DNS MX: {str(e)}")

        # 2. SPF Record Analysis (RFC 7208)
        try:
            txt_records = self.resolver.resolve(clean_domain, "TXT")
            for rdata in txt_records:
                txt_str = "".join([s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if txt_str.startswith("v=spf1"):
                    result["spf_record"] = txt_str
                    if "-all" in txt_str:
                        result["spf_status"] = "STRICT_HARDFAIL (-all)"
                    elif "~all" in txt_str:
                        result["spf_status"] = "PERMISSIVE_SOFTFAIL (~all)"
                        result["dns_security_score"] -= 10
                        result["weaknesses"].append("Política SPF configurada como SoftFail (~all) en lugar de HardFail (-all).")
                        result["recommendations"].append("Migrar directiva SPF de ~all a -all para prevenir suplantación estricta.")
                    elif "?all" in txt_str or "+all" in txt_str:
                        result["spf_status"] = "VULNERABLE_PERMISSIVE (?all / +all)"
                        result["dns_security_score"] -= 30
                        result["weaknesses"].append("Directiva SPF excesivamente permisiva (+all / ?all) que permite spoofing sin penalización.")
                        result["recommendations"].append("Configurar -all en el registro SPF para evitar suplantación abierta.")
                    else:
                        result["spf_status"] = "CONFIGURED"
                    break

            if not result["spf_record"]:
                result["spf_status"] = "MISSING"
                result["dns_security_score"] -= 25
                result["weaknesses"].append("Ausencia de registro SPF (v=spf1). Cualquier servidor puede enviar correo simulando este dominio.")
                result["recommendations"].append("Publicar un registro SPF v=spf1 que declare los remitentes autorizados.")
        except Exception:
            result["spf_status"] = "MISSING"
            result["dns_security_score"] -= 25
            result["weaknesses"].append("Ausencia o timeout al consultar registro SPF.")
            result["recommendations"].append("Configurar registro SPF v=spf1 autoritativo.")

        # 3. DMARC Policy Analysis (RFC 7489)
        dmarc_domain = f"_dmarc.{clean_domain}"
        try:
            dmarc_records = self.resolver.resolve(dmarc_domain, "TXT")
            for rdata in dmarc_records:
                txt_str = "".join([s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if "v=DMARC1" in txt_str or "v=dmarc1" in txt_str:
                    result["dmarc_record"] = txt_str
                    if "p=reject" in txt_str:
                        result["dmarc_status"] = "STRICT_REJECT (p=reject)"
                    elif "p=quarantine" in txt_str:
                        result["dmarc_status"] = "QUARANTINE (p=quarantine)"
                        result["dns_security_score"] -= 5
                        result["recommendations"].append("Avanzar la política DMARC de p=quarantine a p=reject una vez estabilizados los reportes.")
                    elif "p=none" in txt_str:
                        result["dmarc_status"] = "MONITORING_ONLY (p=none)"
                        result["dns_security_score"] -= 20
                        result["weaknesses"].append("Política DMARC en modo pasivo (p=none); no rechaza correos falsificados en tránsito.")
                        result["recommendations"].append("Avanzar política DMARC de p=none a p=quarantine o p=reject.")
                    else:
                        result["dmarc_status"] = "PRESENT"
                    break

            if not result["dmarc_record"]:
                result["dmarc_status"] = "MISSING"
                result["dns_security_score"] -= 30
                result["weaknesses"].append("Dominio carece de registro DMARC (_dmarc). Susceptible a campañas de phishing bajo el nombre corporativo.")
                result["recommendations"].append("Implementar registro DMARC con al menos p=quarantine y buzón rua=mailto:dmarc-reports@dominio.")
        except Exception:
            result["dmarc_status"] = "MISSING"
            result["dns_security_score"] -= 30
            result["weaknesses"].append("Registro DMARC no encontrado en _dmarc." + clean_domain)
            result["recommendations"].append("Configurar DMARC RFC 7489 con política de rechazo.")

        # 4. DKIM Selector Probe (Passive)
        dkim_found = []
        for selector in COMMON_DKIM_SELECTORS:
            try:
                dkim_query = f"{selector}._domainkey.{clean_domain}"
                dkim_ans = self.resolver.resolve(dkim_query, "TXT")
                for rdata in dkim_ans:
                    txt_str = "".join([s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in rdata.strings])
                    if "v=DKIM1" in txt_str or "k=rsa" in txt_str or "p=" in txt_str:
                        dkim_found.append(selector)
                        break
            except Exception:
                continue

        if dkim_found:
            result["dkim_status"] = f"ACTIVE_SELECTORS ({', '.join(dkim_found)})"
        else:
            result["dkim_status"] = "NO_COMMON_SELECTORS_DETECTED"
            result["recommendations"].append("Verificar que la firma criptográfica DKIM esté activa para los selectores corporativos.")

        result["dns_security_score"] = max(0, min(100, result["dns_security_score"]))
        return result
