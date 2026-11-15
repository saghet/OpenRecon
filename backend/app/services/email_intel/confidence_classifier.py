"""
Formal Email Verification & Confidence Classifier for OpenRecon 3.0.
Strictly distinguishes:
- SYNTACTICALLY_VALID
- DOMAIN_HAS_MAIL_INFRA (MX/SPF/DKIM/DMARC)
- REGISTERED_ACCOUNT_CONFIRMED (unambiguous provider confirmation)
- BREACH_ASSOCIATED (verified breach catalog hit)
- AMBIGUOUS_OR_INCONCLUSIVE (never promoted to confirmed existence)
"""

import re
from enum import Enum
from typing import Any, Dict, List

_EMAIL_SYNTAX_RE = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")


class EmailVerificationTier(str, Enum):
    INVALID_SYNTAX = "INVALID_SYNTAX"
    SYNTACTICALLY_VALID = "SYNTACTICALLY_VALID"
    DOMAIN_HAS_MAIL_INFRA = "DOMAIN_HAS_MAIL_INFRA"
    REGISTERED_ACCOUNT_CONFIRMED = "REGISTERED_ACCOUNT_CONFIRMED"
    BREACH_ASSOCIATED = "BREACH_ASSOCIATED"
    AMBIGUOUS_OR_INCONCLUSIVE = "AMBIGUOUS_OR_INCONCLUSIVE"


class EmailVerificationClassifier:
    @staticmethod
    def validate_syntax(email: str) -> bool:
        if not email or len(email) > 320:
            return False
        return bool(_EMAIL_SYNTAX_RE.match(email.strip()))

    @classmethod
    def classify(
        cls,
        email: str,
        domain_intel: Dict[str, Any],
        accounts: List[Dict[str, Any]],
        leaks: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        syntax_ok = cls.validate_syntax(email)
        if not syntax_ok:
            return {
                "email": email,
                "syntax_valid": False,
                "has_mail_infra": False,
                "confirmed_accounts_count": 0,
                "inconclusive_accounts_count": 0,
                "breach_count": 0,
                "tiers": [EmailVerificationTier.INVALID_SYNTAX.value],
                "account_existence_confirmed": False,
            }

        tiers = [EmailVerificationTier.SYNTACTICALLY_VALID.value]
        has_mx = bool(domain_intel.get("mx_records"))
        if has_mx:
            tiers.append(EmailVerificationTier.DOMAIN_HAS_MAIL_INFRA.value)

        confirmed = [
            a for a in accounts
            if a.get("status") == "CONFIRMED" and str(a.get("confidence_level", "")).upper() in ("HIGH", "CONFIRMED")
        ]
        inconclusive = [
            a for a in accounts
            if a.get("status") in ("INCONCLUSIVE", "QUERY_ERROR", "RATE_LIMITED", "AMBIGUOUS")
        ]

        if confirmed:
            tiers.append(EmailVerificationTier.REGISTERED_ACCOUNT_CONFIRMED.value)
        elif inconclusive:
            tiers.append(EmailVerificationTier.AMBIGUOUS_OR_INCONCLUSIVE.value)

        if leaks:
            tiers.append(EmailVerificationTier.BREACH_ASSOCIATED.value)

        return {
            "email": email.strip().lower(),
            "syntax_valid": True,
            "has_mail_infra": has_mx,
            "confirmed_accounts_count": len(confirmed),
            "inconclusive_accounts_count": len(inconclusive),
            "breach_count": len(leaks),
            "tiers": tiers,
            "account_existence_confirmed": bool(confirmed),
        }
