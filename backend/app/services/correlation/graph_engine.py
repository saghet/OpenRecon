"""
Multidimensional Correlation Graph Engine for OpenRecon
Correlates entities across the security lifecycle:
Organization -> Domain -> Subdomain -> IP -> Port -> Service -> Technology -> CVE -> IoC -> Threat -> Threat Actor.
Provides path tracing, confidence evaluation, and temporal relationship analysis.
"""

import logging
from typing import Dict, List, Optional, Any, Set
from datetime import datetime

logger = logging.getLogger(__name__)


class CorrelationGraphEngine:
    """
    In-memory and relational graph representation with multi-hop attack path tracing.
    """

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._adjacency: Dict[str, Set[str]] = {}

    def add_node(
        self,
        node_id: str,
        label: str,
        node_type: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Add or update an entity node in the graph.
        Types: ORG, DOMAIN, SUBDOMAIN, IP, PORT, SERVICE, TECH, CVE, IOC, THREAT, ACTOR.
        """
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "metadata": metadata or {},
                "first_seen": datetime.utcnow().isoformat(),
                "last_seen": datetime.utcnow().isoformat()
            }
            self._adjacency[node_id] = set()
        else:
            self.nodes[node_id]["last_seen"] = datetime.utcnow().isoformat()
            if metadata:
                self.nodes[node_id]["metadata"].update(metadata)

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: str,
        confidence: int = 100,
        evidence: Optional[str] = None
    ) -> None:
        """
        Connect two entities with a typed directed edge and confidence level (0-100).
        """
        if source_id in self.nodes and target_id in self.nodes:
            # Check duplicate edge
            for e in self.edges:
                if e["from"] == source_id and e["to"] == target_id and e["relationship"] == relationship:
                    e["last_verified"] = datetime.utcnow().isoformat()
                    e["confidence"] = confidence
                    return

            edge = {
                "from": source_id,
                "to": target_id,
                "relationship": relationship,
                "confidence": max(0, min(100, confidence)),
                "evidence": evidence or "",
                "created_at": datetime.utcnow().isoformat(),
                "last_verified": datetime.utcnow().isoformat()
            }
            self.edges.append(edge)
            self._adjacency[source_id].add(target_id)

    def build_organization_attack_graph(
        self,
        org_name: str,
        seeds: List[str],
        assets: List[Dict[str, Any]],
        vulns: List[Dict[str, Any]],
        threat_actors: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Construct the end-to-end attack surface and threat correlation graph.
        """
        # 1. Root Organization Node
        org_node_id = f"org_{org_name.lower().replace(' ', '_')}"
        self.add_node(org_node_id, org_name, "ORGANIZATION")

        # 2. Seeds & Domains
        for seed in seeds:
            seed_node_id = f"domain_{seed}"
            self.add_node(seed_node_id, seed, "DOMAIN", {"is_seed": True})
            self.add_edge(org_node_id, seed_node_id, "OWNS", confidence=100)

        # 3. Subdomains and IPs
        for asset in assets:
            sub = asset.get("subdomain") or asset.get("value", "")
            ip = asset.get("ip_address")
            seed = asset.get("seed", seeds[0] if seeds else "")
            seed_node_id = f"domain_{seed}"

            if sub:
                sub_id = f"sub_{sub}"
                self.add_node(sub_id, sub, "SUBDOMAIN", {
                    "is_live": asset.get("is_live", True),
                    "cloud_provider": asset.get("cloud_provider", "Unknown")
                })
                if seed_node_id in self.nodes:
                    self.add_edge(seed_node_id, sub_id, "CONTAINS_SUBDOMAIN", confidence=95)

                if ip:
                    ip_id = f"ip_{ip}"
                    self.add_node(ip_id, ip, "IP_ADDRESS", {"asn": asset.get("asn", "Unknown")})
                    self.add_edge(sub_id, ip_id, "RESOLVES_TO", confidence=100, evidence="DNS A Record")

                    # Open Ports
                    ports = asset.get("ports", [])
                    for p in ports:
                        port_num = p if isinstance(p, int) else p.get("port")
                        service = p.get("service_name", "tcp") if isinstance(p, dict) else "tcp"
                        port_id = f"port_{ip}_{port_num}"
                        self.add_node(port_id, f"{port_num}/{service}", "PORT_SERVICE", {"port": port_num})
                        self.add_edge(ip_id, port_id, "EXPOSES_PORT", confidence=100)

        # 4. Vulnerabilities, CVEs & Exploitation
        for v in vulns:
            sub = v.get("asset_subdomain", "")
            title = v.get("title", "")
            cve_id = v.get("cve_id")
            severity = v.get("severity", "MEDIUM")
            sub_id = f"sub_{sub}"

            if sub_id in self.nodes:
                vuln_id = f"vuln_{abs(hash(sub + title))}"
                self.add_node(vuln_id, title[:40], "VULNERABILITY", {
                    "severity": severity,
                    "validation_state": v.get("validation_state", "POTENCIAL"),
                    "cvss": v.get("cvss_score"),
                    "epss": v.get("epss_score")
                })
                self.add_edge(sub_id, vuln_id, "AFFECTED_BY", confidence=85)

                if cve_id:
                    cve_node_id = f"cve_{cve_id}"
                    self.add_node(cve_node_id, cve_id, "CVE", {
                        "cisa_kev": v.get("cisa_kev", False)
                    })
                    self.add_edge(vuln_id, cve_node_id, "IDENTIFIED_AS", confidence=100)

                    # 5. Link Threat Actors exploiting this CVE/Tactic
                    if threat_actors:
                        for actor in threat_actors:
                            actor_name = actor.get("name", "")
                            tactics = actor.get("mitre_tactics", "")
                            # If actor exploits public facing apps or VPNs (T1190)
                            if "T1190" in tactics or v.get("cisa_kev"):
                                actor_id = f"actor_{abs(hash(actor_name))}"
                                self.add_node(actor_id, actor_name, "THREAT_ACTOR", {
                                    "origin": actor.get("origin"),
                                    "target_sectors": actor.get("target_sectors")
                                })
                                self.add_edge(actor_id, cve_node_id, "ACTIVELY_EXPLOITS", confidence=80, evidence="CISA KEV / Threat Intel Feed")

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes": list(self.nodes.values()),
            "edges": self.edges
        }

    def find_attack_paths_to_critical_assets(self) -> List[List[str]]:
        """
        Trace paths from Threat Actors to exposed Organization assets.
        """
        paths = []
        actor_nodes = [nid for nid, n in self.nodes.items() if n["type"] == "THREAT_ACTOR"]
        subdomain_nodes = [nid for nid, n in self.nodes.items() if n["type"] == "SUBDOMAIN"]

        for actor in actor_nodes:
            visited = set()
            queue = [[actor]]
            while queue:
                path = queue.pop(0)
                current = path[-1]
                if current in subdomain_nodes:
                    paths.append(path)
                    if len(paths) >= 10:
                        return paths
                    continue

                for neighbor in self._adjacency.get(current, []):
                    if neighbor not in visited and len(path) <= 6:
                        visited.add(neighbor)
                        queue.append(path + [neighbor])

        return paths
