import dns.resolver
from typing import List, Dict, Any, Set
import tldextract


class DRPEngine:
    """
    Digital Risk Protection Engine.
    Generates lookalike/typosquatted domains and checks for active registration & MX records.
    """

    def __init__(self, timeout: float = 3.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    def generate_permutations(self, domain: str) -> Set[str]:
        extracted = tldextract.extract(domain)
        name = extracted.domain
        suffix = extracted.suffix

        if not name:
            return set()

        variants = set()

        # 1. Homoglyphs / visually similar
        replacements = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"]}
        for char, subs in replacements.items():
            if char in name:
                for sub in subs:
                    variants.add(f"{name.replace(char, sub)}.{suffix}")

        # 2. Omission of single characters
        for i in range(len(name)):
            variants.add(f"{name[:i] + name[i+1:]}.{suffix}")

        # 3. Common prefixes and suffixes (phishing / fake login)
        for keyword in ["login-", "secure-", "auth-", "-app", "-support", "-corp"]:
            if keyword.endswith("-"):
                variants.add(f"{keyword}{name}.{suffix}")
            else:
                variants.add(f"{name}{keyword}.{suffix}")

        # Remove the exact original domain
        variants.discard(domain)
        # Limit to top 25 high-probability permutations for speed & safety
        return set(list(variants)[:25])

    async def scan_typosquatting(self, domain: str) -> List[Dict[str, Any]]:
        permutations = self.generate_permutations(domain)
        findings = []

        for candidate in permutations:
            is_active = False
            has_mx = False
            resolved_ip = None

            try:
                answers = self.resolver.resolve(candidate, "A")
                if answers:
                    is_active = True
                    resolved_ip = answers[0].to_text()
            except Exception:
                pass

            if is_active:
                try:
                    mx_answers = self.resolver.resolve(candidate, "MX")
                    if mx_answers:
                        has_mx = True
                except Exception:
                    pass

                findings.append({
                    "lookalike_domain": candidate,
                    "resolved_ip": resolved_ip,
                    "has_mx_records": has_mx,
                    "severity": "HIGH" if has_mx else "MEDIUM",
                    "details": f"Active lookalike domain detected. IP: {resolved_ip}. MX (Mail server) active: {has_mx}"
                })

        return findings
