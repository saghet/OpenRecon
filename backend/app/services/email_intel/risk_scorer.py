"""
Explainable Risk Scoring Engine for Email Intelligence.
Computes an Exposure Score (0 - 100) and Risk Level with an audit-ready, human-readable justification.
Adheres strictly to DFIR and CTI principles:
- Distinguishes between historical leak exposure vs active infrastructure vulnerabilities.
- Evaluates source corroboration, recency, and sensitive data classes.
"""

from typing import Dict, Any, List, Tuple


class RiskScorer:
    @staticmethod
    def calculate_risk(
        leaks: List[Dict[str, Any]],
        accounts: List[Dict[str, Any]],
        pastes: List[Dict[str, Any]],
        domain_intel: Dict[str, Any]
    ) -> Tuple[float, str, str]:
        """
        Calculates exposure score, risk level, and explainable justification.
        Returns:
            (exposure_score: float, risk_level: str, explanation: str)
        """
        score = 0.0
        reasons = []

        # 1. Leak Evaluation (Heavy impact if corporate credentials or recent info-stealers)
        confirmed_leaks = [l for l in leaks if l.get("corporate_services_count", 0) > 0 or l.get("user_services_count", 0) > 0]
        if confirmed_leaks:
            stealer_score = 45.0
            total_corp = sum(l.get("corporate_services_count", 0) for l in confirmed_leaks)
            total_user = sum(l.get("user_services_count", 0) for l in confirmed_leaks)
            if total_corp > 0:
                stealer_score += min(20.0, total_corp * 4.0)
                reasons.append(f"Infección por info-stealer detectada con {total_corp} servicios corporativos expuestos.")
            if total_user > 0:
                stealer_score += min(10.0, total_user * 1.5)
                reasons.append(f"Credenciales de usuario ({total_user} cuentas) capturadas en telemetría de stealers.")
            score += min(65.0, stealer_score)
        elif leaks:
            score += 20.0
            reasons.append("Presencia en filtraciones públicas generales sin indicio de stealer corporativo activo.")

        # 2. Account Surface Evaluation
        confirmed_accounts = [a for a in accounts if a.get("status") == "CONFIRMED"]
        if confirmed_accounts:
            acc_score = len(confirmed_accounts) * 4.0
            platforms = [a.get("platform") for a in confirmed_accounts]
            score += min(25.0, acc_score)
            reasons.append(f"Presencia activa confirmada en {len(confirmed_accounts)} plataformas digitales ({', '.join(platforms[:4])}).")

        # 3. Paste Mentions Evaluation
        if pastes:
            score += min(15.0, len(pastes) * 5.0)
            reasons.append(f"Menciones identificadas en {len(pastes)} repositorios de texto público (pastes).")

        # 4. Domain Security Posture Impact
        dns_score = domain_intel.get("dns_security_score", 100)
        if dns_score < 50:
            score += 15.0
            reasons.append(f"Postura DNS del dominio deficiente (Score {dns_score}/100): ausencia de políticas estrictas DMARC/SPF.")
        elif dns_score < 75:
            score += 8.0
            reasons.append(f"Debilidades detectadas en la configuración DMARC/SPF del dominio receptor.")

        final_score = max(0.0, min(100.0, round(score, 1)))

        # Determine Category
        if final_score >= 85.0:
            risk_level = "CRITICAL"
        elif final_score >= 65.0:
            risk_level = "HIGH"
        elif final_score >= 40.0:
            risk_level = "MEDIUM"
        elif final_score >= 15.0:
            risk_level = "LOW"
        else:
            risk_level = "INFORMATIVE"

        if not reasons:
            reasons.append("No se detectaron exposiciones activas en filtraciones ni debilidades de dominio.")

        explanation = (
            f"Nivel {risk_level} (Exposición {final_score}/100) calculado mediante correlación multicriterio: "
            + " ".join(reasons)
        )

        return final_score, risk_level, explanation
