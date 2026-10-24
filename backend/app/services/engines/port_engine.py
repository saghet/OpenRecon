import asyncio
from typing import List, Dict, Any

COMMON_PORTS = [
    (80, "http"),
    (443, "https"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (21, "ftp"),
    (22, "ssh"),
    (25, "smtp"),
    (3389, "ms-wbt-server"),   # RDP
    (3306, "mysql"),           # Database exposed
    (5432, "postgresql"),      # Database exposed
    (6379, "redis"),           # Database exposed
    (9200, "elasticsearch"),   # Search exposed
    (27017, "mongodb")         # Database exposed
]


class PortEngine:
    """
    Asynchronous TCP Port Scanner with safety bounds.
    """

    def __init__(self, timeout: float = 2.5):
        self.timeout = timeout

    async def check_port(self, host: str, port: int, service_name: str) -> Dict[str, Any]:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return {
                "port": port,
                "protocol": "tcp",
                "service_name": service_name,
                "is_open": True
            }
        except Exception:
            return {
                "port": port,
                "protocol": "tcp",
                "service_name": service_name,
                "is_open": False
            }

    async def scan_host(self, host: str, ports: List[tuple] = None) -> List[Dict[str, Any]]:
        target_ports = ports or COMMON_PORTS
        tasks = [self.check_port(host, p[0], p[1]) for p in target_ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r["is_open"]]
