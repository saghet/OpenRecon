"""
Email Variant Generator for Email Intelligence.
Generates structured hypothesis permutations for identity correlation (e.g. corporate vs
personal aliases, typosquatting domains, prefix mutations).

CRITICAL OSINT & ETHICAL RULE:
All generated addresses are mathematical hypotheses and MUST NEVER be presented as confirmed accounts.
NO active network probes (e.g., SMTP RCPT TO, sending emails) are allowed.
Only passive MX DNS presence checks are applied to determine domain routability.
"""

import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger("email_intel.email_generator")

COMMON_WEBMAIL_DOMAINS = [
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "proton.me",
    "icloud.com",
    "zoho.com"
]


class EmailGenerator:
    def __init__(self, alternative_domains: List[str] = None):
        self.domains = alternative_domains or COMMON_WEBMAIL_DOMAINS

    def generate_variants(self, base_email: str) -> List[Dict[str, Any]]:
        """
        Generates distinct permutations classified by heuristic pattern.
        """
        clean_email = base_email.strip().lower()
        if "@" not in clean_email:
            return []

        local_part, base_domain = clean_email.split("@", 1)
        variants = []
        seen = set()

        def add_variant(var_local: str, dom: str, domain_type: str, pattern: str):
            candidate = f"{var_local}@{dom}".lower()
            if candidate != clean_email and candidate not in seen:
                seen.add(candidate)
                variants.append({
                    "base_email": clean_email,
                    "variant_email": candidate,
                    "domain_type": domain_type,
                    "pattern_type": pattern,
                    "classification": "HYPOTHESIS_UNVERIFIED",
                    "passive_mx_valid": False
                })

        # Pattern 1: Same local part across common webmail domains
        for dom in self.domains:
            if dom != base_domain:
                add_variant(local_part, dom, "ALTERNATIVE_WEBMAIL", "SAME_HANDLE_DIFFERENT_DOMAIN")

        # Pattern 2: Split by dot, underscore, or hyphen (e.g. john.doe)
        tokens = re.split(r"[._\-]", local_part)
        if len(tokens) >= 2:
            first = tokens[0]
            last = tokens[-1]
            # john.doe -> jdoe
            add_variant(f"{first[0]}{last}", base_domain, "SAME_DOMAIN", "INITIAL_LASTNAME")
            # john.doe -> doe.john
            add_variant(f"{last}.{first}", base_domain, "SAME_DOMAIN", "REVERSED_NAME")
            # john.doe -> johndoe
            add_variant(f"{first}{last}", base_domain, "SAME_DOMAIN", "CONCATENATED")
            # john.doe -> john_doe
            add_variant(f"{first}_{last}", base_domain, "SAME_DOMAIN", "UNDERSCORE_SEPARATOR")
            # john.doe -> john-doe
            add_variant(f"{first}-{last}", base_domain, "SAME_DOMAIN", "HYPHEN_SEPARATOR")

        # Pattern 3: Stripping numbers (e.g. jdoe2024 -> jdoe)
        stripped_digits = re.sub(r"\d+", "", local_part)
        if stripped_digits and stripped_digits != local_part:
            add_variant(stripped_digits, base_domain, "SAME_DOMAIN", "STRIP_TRAILING_DIGITS")

        # Pattern 4: Adding standard corporate year/dept tags
        add_variant(f"{local_part}.corp", base_domain, "SAME_DOMAIN", "CORP_SUFFIX")

        return variants[:20]  # Cap at top 20 relevant hypotheses
