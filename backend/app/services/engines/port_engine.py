import asyncio
import json
import logging
import shutil
from typing import Any, Dict, List, Optional

from app.core.security_guard import SecurityGovernanceGuard

logger = logging.getLogger(__name__)

COMMON_PORTS = [
    (80, "http"),
    (443, "https"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (21, "ftp"),
    (22, "ssh"),
    (25, "smtp"),
    (3389, "ms-wbt-server"),
    (3306, "mysql"),
    (5432, "postgresql"),
    (6379, "redis"),
    (9200, "elasticsearch"),
    (27017, "mongodb"),
]

_PORT_SERVICE_MAP = {p: name for p, name in COMMON_PORTS}


class PortEngine:
    """
    Asynchronous TCP Port Scanner with safety bounds.
    Prioritizes ProjectDiscovery `naabu` (connect mode, rate-limited JSON) when installed,
    with a bounded asyncio.open_connection fallback.
    """

    def __init__(self, timeout: float = 2.5, max_concurrency: int = 20, rate_limit: int = 100):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.rate_limit = rate_limit
        self.has_naabu = shutil.which("naabu") is not None

    @staticmethod
    def parse_naabu_json(raw_stdout: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        seen_ports = set()
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            port = obj.get("port")
            if port is None or port in seen_ports:
                continue
            seen_ports.add(int(port))
            results.append({
                "port": int(port),
                "protocol": str(obj.get("protocol", "tcp")).lower(),
                "service_name": _PORT_SERVICE_MAP.get(int(port), f"tcp-{port}"),
                "ip": obj.get("ip"),
                "is_open": True,
                "detector": "naabu",
            })
        return results

    async def _scan_with_naabu(self, host: str, port_list: List[int]) -> Optional[List[Dict[str, Any]]]:
        if not self.has_naabu:
            return None
        ports_arg = ",".join(str(p) for p in port_list)
        try:
            proc = await asyncio.create_subprocess_exec(
                "naabu",
                "-host", host,
                "-p", ports_arg,
                "-s", "c",  # Unprivileged TCP connect scan (no root raw-socket required)
                "-rate", str(self.rate_limit),
                "-timeout", str(int(self.timeout * 1000)),
                "-json",
                "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=max(15.0, self.timeout * 10))
            return self.parse_naabu_json(stdout.decode("utf-8", errors="ignore"))
        except Exception as e:
            logger.warning(f"naabu scan failed for {host}, using asyncio fallback: {e}")
            return None

    async def check_port(self, host: str, port: int, service_name: str, sem: Optional[asyncio.Semaphore] = None) -> Dict[str, Any]:
        async def _probe():
            try:
                conn = asyncio.open_connection(host, port)
                _reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return {
                    "port": port,
                    "protocol": "tcp",
                    "service_name": service_name,
                    "is_open": True,
                    "detector": "asyncio_tcp",
                }
            except Exception:
                return {
                    "port": port,
                    "protocol": "tcp",
                    "service_name": service_name,
                    "is_open": False,
                    "detector": "asyncio_tcp",
                }

        if sem is not None:
            async with sem:
                return await _probe()
        return await _probe()

    async def scan_host(self, host: str, ports: Optional[List[tuple]] = None, allow_local_lab: bool = False) -> List[Dict[str, Any]]:
        ks = SecurityGovernanceGuard.is_kill_switch_active()
        if ks.get("active"):
            logger.warning(f"PortEngine aborted for {host}: Kill-Switch active")
            return []

        if not allow_local_lab:
            safety = SecurityGovernanceGuard.validate_target_safety(host)
            if not safety.get("safe"):
                logger.warning(f"PortEngine blocked {host}: {safety.get('reason')}")
                return []

        target_ports = ports or COMMON_PORTS
        port_nums = [int(p[0]) for p in target_ports]

        naabu_res = await self._scan_with_naabu(host, port_nums)
        if naabu_res is not None:
            return naabu_res

        sem = asyncio.Semaphore(self.max_concurrency)
        tasks = [self.check_port(host, int(p[0]), str(p[1]), sem=sem) for p in target_ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r["is_open"]]
