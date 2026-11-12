"""
Intelligent Explainable Risk Engine for OpenRecon
Calculates dynamic Exposure Score (0-100) using multi-factor threat modeling:
CVSS v3.1 + EPSS Exploitability + CISA KEV In-The-Wild + Public Exposure +
Asset Criticality + Ransomware Intelligence + Validation State Adjustment.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime


class IntelligentRiskEngine:
    """
    Production-grade risk calculator with transparent, explainable scoring criteria.
    """

    def __init__(self, custom_weights: Optional[Dict[str, float]] = None):
        # Default balanced enterprise weights (summing to 1.0)
        self.weights = custom_weights or {
            "cvss_severity": 0.25,
            "epss_probability": 0.20,
            "cisa_kev_active": 0.25,
            "exposure_reachability": 0.15,
            "ransomware_threat": 0.15
        }

    def calculate_vulnerability_risk(
        self,
        vuln: Dict[str, Any],
        asset: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Calculate individual vulnerability risk score (0-100) with detailed explanation.
        """
        # 1. CVSS Base (0 - 10 -> normalized to 0 - 100)
        cvss = float(vuln.get("cvss_score") or vuln.get("cvss") or 0.0)
        if cvss == 0.0:
            severity = str(vuln.get("severity", "MEDIUM")).upper()
            sev_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.5}
            cvss = sev_map.get(severity, 5.0)
        score_cvss = min(100.0, cvss * 10.0)

        # 2. EPSS Score (0.0 - 1.0 -> 0 - 100)
        epss = float(vuln.get("epss_score") or vuln.get("epss") or 0.0)
        score_epss = min(100.0, epss * 100.0)

        # 3. CISA KEV (Boolean -> 0 or 100)
        in_cisa_kev = bool(vuln.get("cisa_kev", False))
        score_kev = 100.0 if in_cisa_kev else 0.0

        # 4. Exposure & Reachability
        validation_state = str(vuln.get("validation_state", "POTENCIAL")).upper()
        if validation_state == "FALSO_POSITIVO":
            # False positives carry 0 risk
            return {
                "score": 0.0,
                "tier": "INFORMATIVO",
                "validation_state": "FALSO_POSITIVO",
                "explanation": "Descartado como falso positivo; no contribuye a la postura de riesgo.",
                "components": {}
            }
        elif validation_state == "MITIGADA":
            return {
                "score": 5.0,
                "tier": "INFORMATIVO",
                "validation_state": "MITIGADA",
                "explanation": "Mitigación técnica verificada en el perímetro.",
                "components": {}
            }
        elif validation_state == "RIESGO_ACEPTADO":
            return {
                "score": 15.0,
                "tier": "BAJO",
                "validation_state": "RIESGO_ACEPTADO",
                "explanation": "Riesgo formalmente aceptado (endpoint 403 o no explotable).",
                "components": {}
            }

        is_live = asset.get("is_live", True) if asset else True
        score_exposure = 90.0 if is_live else 20.0

        # 5. Ransomware & Threat Intelligence Flag
        ransomware_flag = bool(vuln.get("ransomware_campaign_use", False))
        score_ransomware = 100.0 if ransomware_flag else (50.0 if in_cisa_kev else 10.0)

        # Weighted calculation
        raw_score = (
            score_cvss * self.weights["cvss_severity"] +
            score_epss * self.weights["epss_probability"] +
            score_kev * self.weights["cisa_kev_active"] +
            score_exposure * self.weights["exposure_reachability"] +
            score_ransomware * self.weights["ransomware_threat"]
        )

        # Validation state adjustment multiplier
        if validation_state == "CONFIRMADA":
            final_score = min(100.0, raw_score * 1.15)
        elif validation_state == "PROBABLE":
            final_score = raw_score
        else:  # POTENCIAL or INFO_INSUFICIENTE
            final_score = raw_score * 0.75

        final_score = round(final_score, 1)

        # Risk Tier
        if final_score >= 90.0:
            tier = "CRÍTICO"
        elif final_score >= 70.0:
            tier = "ALTO"
        elif final_score >= 40.0:
            tier = "MEDIO"
        elif final_score >= 20.0:
            tier = "BAJO"
        else:
            tier = "INFORMATIVO"

        explanation = (
            f"Vulnerabilidad evaluada con severidad técnica CVSS {cvss}/10 "
            f"({score_cvss:.0f} pts). Probabilidad de explotación EPSS {epss:.1%} "
            f"({score_epss:.0f} pts). "
            f"{'Presente en catálogo CISA KEV bajo explotación activa en Internet. ' if in_cisa_kev else ''}"
            f"Estado de validación: {validation_state}."
        )

        return {
            "score": final_score,
            "tier": tier,
            "validation_state": validation_state,
            "explanation": explanation,
            "components": {
                "cvss_component": round(score_cvss * self.weights["cvss_severity"], 1),
                "epss_component": round(score_epss * self.weights["epss_probability"], 1),
                "kev_component": round(score_kev * self.weights["cisa_kev_active"], 1),
                "exposure_component": round(score_exposure * self.weights["exposure_reachability"], 1),
                "ransomware_component": round(score_ransomware * self.weights["ransomware_threat"], 1)
            }
        }

    def calculate_organization_posture_score(
        self,
        vulnerabilities: List[Dict[str, Any]],
        total_assets: int,
        ransomware_matched_count: int = 0
    ) -> Dict[str, Any]:
        """
        Computes the global executive Exposure Score (0-100) for an organization.
        0 = Pristine security posture, 100 = Imminent compromise hazard.
        """
        if not vulnerabilities and ransomware_matched_count == 0:
            return {
                "exposure_score": 10.0,
                "posture": "EXCELLENT",
                "summary": "Perímetro limpio sin vulnerabilidades activas detectadas.",
                "metrics": {"total_vulns": 0, "active_assets": total_assets}
            }

        scores = []
        confirmed_count = 0
        kev_count = 0

        for v in vulnerabilities:
            res = self.calculate_vulnerability_risk(v)
            if res["validation_state"] not in ["FALSO_POSITIVO", "MITIGADA"]:
                scores.append(res["score"])
                if res["validation_state"] == "CONFIRMADA":
                    confirmed_count += 1
                if v.get("cisa_kev"):
                    kev_count += 1

        if not scores:
            base_score = 15.0
        else:
            # Emphasize top highest severity vulnerabilities
            sorted_scores = sorted(scores, reverse=True)
            top_scores = sorted_scores[:5]
            base_score = sum(top_scores) / len(top_scores)

        # Penalty for active ransomware leak match
        if ransomware_matched_count > 0:
            base_score = min(100.0, base_score + (ransomware_matched_count * 15.0))

        exposure_score = round(min(100.0, base_score), 1)

        if exposure_score >= 80.0:
            posture = "CRITICAL_EXPOSURE"
        elif exposure_score >= 60.0:
            posture = "HIGH_RISK"
        elif exposure_score >= 35.0:
            posture = "MODERATE_RISK"
        else:
            posture = "GOOD_POSTURE"

        return {
            "exposure_score": exposure_score,
            "posture": posture,
            "metrics": {
                "evaluated_vulnerabilities": len(scores),
                "confirmed_vulnerabilities": confirmed_count,
                "cisa_kev_active": kev_count,
                "ransomware_matched_leaks": ransomware_matched_count,
                "monitored_assets": total_assets
            },
            "weights_used": self.weights
        }
