import asyncio
import json
import logging
import re
import shutil
from typing import Any, Dict, List, Optional

import httpx

from app.core.security_guard import SecurityGovernanceGuard
from app.core.tls_config import get_httpx_verify, probe_tls_certificate
from app.services.web_security.analyzer import WebSecurityAnalyzer

logger = logging.getLogger(__name__)


class HTTPEngine:
    """
    HTTP/HTTPS Service Fingerprinting Engine.
    Prioritizes ProjectDiscovery `httpx` CLI (JSONL) when installed, with
    a safe async fallback using Python `httpx` + strict TLS verification.
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout
        self.has_httpx_bin = shutil.which("httpx") is not None

    @staticmethod
    def parse_httpx_jsonl(raw_stdout: str) -> Optional[Dict[str, Any]]:
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            tls_obj = obj.get("tls") or {}
            techs = obj.get("tech") or []
            if not isinstance(techs, list):
                techs = [str(techs)]
            webserver = obj.get("webserver")
            if webserver and webserver not in techs:
                techs.append(webserver)
            return {
                "status_code": obj.get("status_code"),
                "web_title": (obj.get("title") or "")[:200] or None,
                "server": webserver,
                "tech_stack": techs,
                "ssl_issuer": tls_obj.get("issuer_org") or tls_obj.get("issuer_cn"),
                "ssl_expiry": tls_obj.get("not_after"),
                "tls_valid": not bool(tls_obj.get("expired", False)) if tls_obj else None,
                "tls_error": None,
                "detector": "projectdiscovery_httpx",
            }
        return None

    async def _probe_with_binary(self, url: str) -> Optional[Dict[str, Any]]:
        if not self.has_httpx_bin:
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                "httpx",
                "-u", url,
                "-json",
                "-title",
                "-status-code",
                "-tech-detect",
                "-tls-grab",
                "-silent",
                "-no-color",
                "-timeout", str(int(max(1, self.timeout))),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 10.0)
            return self.parse_httpx_jsonl(stdout.decode("utf-8", errors="ignore"))
        except Exception as e:
            logger.warning(f"httpx binary probe failed for {url}: {e}")
            return None

    async def probe(self, host: str, port: int = 443) -> Dict[str, Any]:
        is_ssl = port in (443, 8443)
        scheme = "https" if is_ssl else "http"
        url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"

        result: Dict[str, Any] = {
            "status_code": None,
            "web_title": None,
            "server": None,
            "tech_stack": [],
            "ssl_issuer": None,
            "ssl_expiry": None,
            "tls_valid": None,
            "tls_error": None,
            "detector": "httpx_python_fallback",
        }

        # Anti-SSRF & Kill-Switch guard before probing
        ks = SecurityGovernanceGuard.is_kill_switch_active()
        if ks.get("active"):
            result["tls_error"] = f"Aborted by Kill-Switch: {ks.get('reason')}"
            return result

        safety = SecurityGovernanceGuard.validate_target_safety(url)
        if not safety.get("safe"):
            result["tls_error"] = f"Blocked by Anti-SSRF: {safety.get('reason')}"
            return result

        # Prefer ProjectDiscovery httpx binary when available
        bin_res = await self._probe_with_binary(url)
        if bin_res is not None:
            return bin_res

        if is_ssl:
            ssl_info = self.get_ssl_info(host, port)
            result["ssl_issuer"] = ssl_info.get("issuer")
            result["ssl_expiry"] = ssl_info.get("expiry")
            result["tls_valid"] = ssl_info.get("tls_valid")
            result["tls_error"] = ssl_info.get("error")

        try:
            async with httpx.AsyncClient(verify=get_httpx_verify(), timeout=self.timeout, follow_redirects=False) as client:
                headers = {"User-Agent": "OpenRecon-Scanner/3.0"}
                resp = await client.get(url, headers=headers)
                result["status_code"] = resp.status_code

                server = resp.headers.get("server")
                if server:
                    result["server"] = server
                    result["tech_stack"].append(server)

                match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if match:
                    result["web_title"] = match.group(1).strip()[:200]

                body = resp.text.lower()
                if "wp-content" in body or "wp-includes" in body:
                    result["tech_stack"].append("WordPress")
                if "x-powered-by" in resp.headers:
                    result["tech_stack"].append(resp.headers["x-powered-by"])
                if server and "cloudflare" in server.lower():
                    result["tech_stack"].append("Cloudflare")
                if "laravel" in body or "laravel_session" in resp.headers.get("set-cookie", ""):
                    result["tech_stack"].append("Laravel")
                if "react" in body or "next" in body:
                    result["tech_stack"].append("React/Next.js")

                result["security_headers_findings"] = WebSecurityAnalyzer.analyze_headers(
                    dict(resp.headers), is_https=is_ssl
                )

        except Exception as exc:
            logger.debug(f"HTTPEngine fallback probe error for {url}: {exc}")

        return result

    def get_ssl_info(self, host: str, port: int) -> Dict[str, Optional[Any]]:
        tls_data = probe_tls_certificate(host, port, timeout=self.timeout)
        return {
            "issuer": tls_data.get("issuer"),
            "expiry": tls_data.get("not_after"),
            "tls_valid": tls_data.get("tls_valid"),
            "expired": tls_data.get("expired"),
            "error": tls_data.get("error"),
        }
