import shutil
import subprocess
import json
import logging
import dns.resolver
import httpx
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)


class DNSEngine:
    """
    Hybrid DNS and Subdomain Discovery Engine.
    Leverages `subfinder` if available, and falls back to crt.sh + dnspython queries.
    """

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.has_subfinder = shutil.which("subfinder") is not None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        # Using reputable public DNS resolvers
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    async def discover_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        subdomains: Set[str] = set()

        # Method 1: Subfinder (if installed in system)
        if self.has_subfinder:
            try:
                cmd = ["subfinder", "-d", domain, "-silent", "-all"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        clean = line.strip().lower()
                        if clean and domain in clean:
                            subdomains.add(clean)
            except Exception as e:
                logger.warning(f"Subfinder execution error: {e}")

        # Method 2: Fallback / Complement with crt.sh (Certificate Transparency logs)
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub and domain in sub and not any(c in sub for c in ["@", " "]):
                                subdomains.add(sub)
        except Exception as e:
            logger.warning(f"crt.sh query failed for {domain}: {e}")

        # Ensure base domain is also checked
        subdomains.add(domain)

        # Resolve IPs for discovered subdomains
        results: List[Dict[str, Any]] = []
        for sub in subdomains:
            resolved_ip, cloud_hint = self.resolve_host(sub)
            results.append({
                "subdomain": sub,
                "ip_address": resolved_ip,
                "is_live": resolved_ip is not None,
                "cloud_provider": cloud_hint,
                "discovery_source": "subfinder" if self.has_subfinder else "crt.sh+dns"
            })

        return results

    def resolve_host(self, hostname: str):
        try:
            answers = self.resolver.resolve(hostname, "A")
            for rdata in answers:
                ip = rdata.to_text()
                # Simple cloud / CDN detection
                cloud = None
                if ip.startswith("104.") or ip.startswith("172.67."):
                    cloud = "Cloudflare"
                elif ip.startswith("52.") or ip.startswith("54.") or ip.startswith("3."):
                    cloud = "AWS"
                elif ip.startswith("34.") or ip.startswith("35."):
                    cloud = "Google Cloud"
                elif ip.startswith("20.") or ip.startswith("40."):
                    cloud = "Microsoft Azure"
                return ip, cloud
        except Exception:
            pass
        return None, None
