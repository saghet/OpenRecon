import json
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.organization import Organization, Seed, SeedType
from app.models.asset import Asset, AssetType
from app.models.exposure import PortService, Vulnerability, DigitalRiskFinding, SeverityLevel, RiskType
from app.models.scan import ScanJob, ScanStatus, ScanType
from app.services.engines.dns_engine import DNSEngine
from app.services.engines.http_engine import HTTPEngine
from app.services.engines.port_engine import PortEngine
from app.services.engines.drp_engine import DRPEngine
from app.services.engines.nuclei_engine import NucleiEngine

logger = logging.getLogger(__name__)


class ScannerOrchestrator:
    """
    Central Orchestrator coordinating EASM, DRP and Exposure detection pipelines.
    """

    def __init__(self, db: Session):
        self.db = db
        self.dns_engine = DNSEngine()
        self.http_engine = HTTPEngine()
        self.port_engine = PortEngine()
        self.drp_engine = DRPEngine()
        self.nuclei_engine = NucleiEngine()

    async def execute_scan(self, scan_job_id: int):
        scan_job = self.db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not scan_job:
            logger.error(f"Scan job {scan_job_id} not found.")
            return

        scan_job.status = ScanStatus.RUNNING
        scan_job.started_at = datetime.utcnow()
        self.db.commit()

        org_id = scan_job.organization_id
        seeds = self.db.query(Seed).filter(Seed.organization_id == org_id, Seed.is_active == 1).all()

        total_assets_found = 0
        total_vulns_found = 0
        total_drp_found = 0

        try:
            for seed in seeds:
                if seed.seed_type == SeedType.DOMAIN:
                    domain = seed.value.strip().lower()
                    
                    # 1. DNS & Subdomain Discovery
                    discovered_subs = await self.dns_engine.discover_subdomains(domain)
                    scan_job.total_targets += len(discovered_subs)
                    self.db.commit()

                    for sub_data in discovered_subs:
                        hostname = sub_data["subdomain"]
                        ip = sub_data["ip_address"]
                        is_live = sub_data["is_live"]
                        cloud_provider = sub_data["cloud_provider"]

                        # Check or create asset
                        asset = self.db.query(Asset).filter(
                            Asset.organization_id == org_id,
                            Asset.value == hostname
                        ).first()

                        if not asset:
                            asset = Asset(
                                organization_id=org_id,
                                seed_id=seed.id,
                                asset_type=AssetType.SUBDOMAIN,
                                value=hostname,
                                ip_address=ip,
                                cloud_provider=cloud_provider,
                                is_live=is_live,
                                discovery_source=sub_data["discovery_source"],
                                first_seen=datetime.utcnow(),
                                last_seen=datetime.utcnow()
                            )
                            self.db.add(asset)
                            self.db.flush()
                            total_assets_found += 1
                        else:
                            asset.ip_address = ip
                            asset.is_live = is_live
                            asset.last_seen = datetime.utcnow()

                        # 2. Port & Service Scanning on live hosts
                        if is_live and (scan_job.scan_type in [ScanType.EASM_FULL, ScanType.PORT_SCAN]):
                            target_host = ip if ip else hostname
                            open_ports = await self.port_engine.scan_host(target_host)

                            for p in open_ports:
                                port_num = p["port"]
                                service_name = p["service_name"]

                                # HTTP Probe if web port
                                web_title = None
                                status_code = None
                                tech_stack_str = None
                                ssl_issuer = None
                                ssl_expiry = None

                                if port_num in (80, 443, 8080, 8443):
                                    http_res = await self.http_engine.probe(hostname, port_num)
                                    web_title = http_res.get("web_title")
                                    status_code = http_res.get("status_code")
                                    tech_stack_str = ", ".join(http_res.get("tech_stack", []))
                                    ssl_issuer = http_res.get("ssl_issuer")
                                    ssl_expiry = http_res.get("ssl_expiry")

                                # Check or create port entry
                                port_entry = self.db.query(PortService).filter(
                                    PortService.asset_id == asset.id,
                                    PortService.port == port_num
                                ).first()

                                if not port_entry:
                                    port_entry = PortService(
                                        asset_id=asset.id,
                                        port=port_num,
                                        protocol="tcp",
                                        service_name=service_name,
                                        web_title=web_title,
                                        status_code=status_code,
                                        tech_stack=tech_stack_str,
                                        ssl_issuer=ssl_issuer,
                                        ssl_expiry=ssl_expiry
                                    )
                                    self.db.add(port_entry)
                                else:
                                    if web_title:
                                        port_entry.web_title = web_title
                                    if status_code:
                                        port_entry.status_code = status_code
                                    if tech_stack_str:
                                        port_entry.tech_stack = tech_stack_str

                                # Rule-based exposure analysis: Dangerous ports exposed publicly
                                if port_num in [3306, 5432, 6379, 27017, 9200]:
                                    vuln_title = f"Exposed Database Service: {service_name.upper()} on port {port_num}"
                                    existing_vuln = self.db.query(Vulnerability).filter(
                                        Vulnerability.asset_id == asset.id,
                                        Vulnerability.title == vuln_title
                                    ).first()
                                    if not existing_vuln:
                                        vuln = Vulnerability(
                                            asset_id=asset.id,
                                            title=vuln_title,
                                            severity=SeverityLevel.HIGH,
                                            description=f"Database port {port_num} ({service_name}) is exposed directly to the internet without firewall boundary.",
                                            remediation=f"Restrict access to port {port_num} via firewall / security group to authorized IP ranges or private VPN only.",
                                            detector="port_exposure_rule"
                                        )
                                        self.db.add(vuln)
                                        total_vulns_found += 1
                                elif port_num in [21, 3389]:
                                    vuln_title = f"Exposed Remote Management Port: {service_name.upper()} ({port_num})"
                                    existing_vuln = self.db.query(Vulnerability).filter(
                                        Vulnerability.asset_id == asset.id,
                                        Vulnerability.title == vuln_title
                                    ).first()
                                    if not existing_vuln:
                                        vuln = Vulnerability(
                                            asset_id=asset.id,
                                            title=vuln_title,
                                            severity=SeverityLevel.MEDIUM if port_num == 21 else SeverityLevel.HIGH,
                                            description=f"Administrative service on port {port_num} is exposed to the public internet.",
                                            remediation="Disable unencrypted/public administrative access and enforce bastion or VPN access.",
                                            detector="port_exposure_rule"
                                        )
                                        self.db.add(vuln)
                                        total_vulns_found += 1

                            # Nuclei validation if available
                            if self.nuclei_engine.has_nuclei:
                                nuclei_results = await self.nuclei_engine.scan_target(f"https://{hostname}")
                                for nr in nuclei_results:
                                    v = Vulnerability(
                                        asset_id=asset.id,
                                        title=nr["title"],
                                        severity=getattr(SeverityLevel, nr["severity"], SeverityLevel.INFO),
                                        cve_id=nr["cve_id"],
                                        cvss_score=nr["cvss_score"],
                                        epss_score=nr["epss_score"],
                                        description=nr["description"],
                                        remediation=nr["remediation"],
                                        detector="nuclei",
                                        template_id=nr["template_id"]
                                    )
                                    self.db.add(v)
                                    total_vulns_found += 1

                        scan_job.processed_targets += 1
                        self.db.commit()

                    # 3. DRP Scan (Typosquatting & Lookalike Domains)
                    if scan_job.scan_type in [ScanType.EASM_FULL, ScanType.DRP_SCAN]:
                        drp_results = await self.drp_engine.scan_typosquatting(domain)
                        for drp_item in drp_results:
                            target_val = drp_item["lookalike_domain"]
                            existing_drp = self.db.query(DigitalRiskFinding).filter(
                                DigitalRiskFinding.organization_id == org_id,
                                DigitalRiskFinding.target_value == target_val
                            ).first()

                            if not existing_drp:
                                drp_record = DigitalRiskFinding(
                                    organization_id=org_id,
                                    risk_type=RiskType.TYPOSQUATTING,
                                    target_value=target_val,
                                    severity=getattr(SeverityLevel, drp_item["severity"], SeverityLevel.MEDIUM),
                                    details=drp_item["details"],
                                    source="dnstwist_heuristics"
                                )
                                self.db.add(drp_record)
                                total_drp_found += 1
                        self.db.commit()

            # Finish job
            scan_job.status = ScanStatus.COMPLETED
            scan_job.finished_at = datetime.utcnow()
            scan_job.summary = json.dumps({
                "assets_cataloged": total_assets_found,
                "vulnerabilities_detected": total_vulns_found,
                "drp_findings": total_drp_found
            })
            self.db.commit()

        except Exception as e:
            logger.exception("Scan job execution failed")
            scan_job.status = ScanStatus.FAILED
            scan_job.error_log = str(e)
            scan_job.finished_at = datetime.utcnow()
            self.db.commit()
