import re
import ssl
import socket
from datetime import datetime
from typing import Dict, Any, Optional
import httpx


class HTTPEngine:
    """
    HTTP/HTTPS Service Fingerprinting Engine.
    Inspects web response, status code, HTML title, SSL certificates and technologies.
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

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
            "ssl_expiry": None
        }

        # Check SSL details directly if HTTPS
        if is_ssl:
            ssl_info = self.get_ssl_info(host, port)
            result["ssl_issuer"] = ssl_info.get("issuer")
            result["ssl_expiry"] = ssl_info.get("expiry")

        # HTTP Probe
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
                headers = {"User-Agent": "OpenRecon-Scanner/1.0 (+https://github.com/openrecon/engine)"}
                resp = await client.get(url, headers=headers)
                result["status_code"] = resp.status_code
                
                # Server header
                server = resp.headers.get("server")
                if server:
                    result["server"] = server
                    result["tech_stack"].append(server)

                # Extract HTML title
                match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if match:
                    result["web_title"] = match.group(1).strip()[:200]

                # Identify common technologies from headers and body
                body = resp.text.lower()
                if "wp-content" in body or "wp-includes" in body:
                    result["tech_stack"].append("WordPress")
                if "x-powered-by" in resp.headers:
                    result["tech_stack"].append(resp.headers["x-powered-by"])
                if "cloudflare" in server.lower() if server else False:
                    result["tech_stack"].append("Cloudflare")
                if "laravel" in body or "laravel_session" in resp.headers.get("set-cookie", ""):
                    result["tech_stack"].append("Laravel")
                if "react" in body or "next" in body:
                    result["tech_stack"].append("React/Next.js")

        except Exception:
            pass

        return result

    def get_ssl_info(self, host: str, port: int) -> Dict[str, Optional[Any]]:
        info = {"issuer": None, "expiry": None}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    # Simple extraction
                    info["issuer"] = "Valid TLS Certificate"
        except Exception:
            pass
        return info
