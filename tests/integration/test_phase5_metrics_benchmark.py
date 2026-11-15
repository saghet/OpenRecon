"""
FASE 5 — Controlled Benchmark & 10 Mandatory Metrics Measurement.
Measures before/after on a controlled dataset (no unauthorized external scanning):
1. Finding precision
2. False-positive rate
3. Duplicate rate
4. Asset coverage
5. % results with evidence
6. % verified findings
7. Average investigation/pipeline time
8. CPU time & peak RAM (tracemalloc)
9. Provider error rate (with Circuit Breaker)
10. % results persisted in SQLite
"""

import os
import sys
import tempfile
import time
import tracemalloc
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from app.core.database import Base
from app.models.evidence import EvidenceRecord, FindingValidationState
from app.models.domain_intel import ProviderQueryStatus
from app.services.domain_intel.base import ProviderResponse
from app.services.domain_intel.service import DomainIntelligenceService
from app.services.engines.dns_engine import DNSEngine
from app.services.evidence.manager import EvidenceManager
from app.services.validation.anti_false_positive import AntiFalsePositiveEngine, CandidateFinding
from app.services.validation.finding_contract import GlobalFindingDeduplicator, NormalizedFinding


class TestPhase5MetricsBenchmark(unittest.IsolatedAsyncioTestCase):
    async def test_01_measure_10_mandatory_metrics_controlled_dataset(self):
        # Controlled dataset:
        # - 10 real subdomains + 10 wildcard noise subdomains
        # - 40 raw findings: 20 true positives (10 unique x 2 sources), 10 false positives (failed 2nd check), 10 empty-evidence noise
        engine = DNSEngine()
        engine.has_subfinder = True
        engine.has_amass = False

        real_subs = {f"svc{i}.example.com": {"subfinder:crtsh"} for i in range(10)}
        wc_subs = {f"rand{i}.example.com": {"subfinder:brute"} for i in range(10)}

        async def mock_subfinder(_d):
            merged = {}
            merged.update(real_subs)
            merged.update(wc_subs)
            return merged

        async def mock_crtsh(_d):
            return {"svc0.example.com": {"crt.sh"}}

        def mock_resolve(host):
            if host.startswith("openrecon-wc-") or host.startswith("rand"):
                return {"198.51.100.99"}
            return {"93.184.216.34"}

        with (
            patch.object(engine, "_run_subfinder", side_effect=mock_subfinder),
            patch.object(engine, "_query_crtsh", side_effect=mock_crtsh),
            patch.object(engine, "_resolve_all_a", side_effect=mock_resolve),
        ):
            discovered = await engine.discover_subdomains("example.com")

        discovered_hosts = {d["subdomain"] for d in discovered}
        # 10 real subdomains + apex example.com = 11; 0 wildcard noise
        asset_coverage = sum(1 for h in real_subs if h in discovered_hosts) / len(real_subs)
        wildcard_fp_rate = sum(1 for h in wc_subs if h in discovered_hosts) / len(wc_subs)

        # In-memory isolated SQLite for persistence measurement
        db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        try:
            sql_engine = create_engine(f"sqlite:///{db_file}")
            Base.metadata.create_all(bind=sql_engine)
            SessionLocal = sessionmaker(bind=sql_engine)
            db = SessionLocal()

            tracemalloc.start()
            t_wall_0 = time.perf_counter()
            t_cpu_0 = time.process_time()

            dedup = GlobalFindingDeduplicator()
            afp = AntiFalsePositiveEngine()
            ev_mgr = EvidenceManager(db)

            raw_findings = []
            # 10 unique TPs reported by 2 sources = 20 items
            for i in range(10):
                for src in ("nuclei", "httpx"):
                    raw_findings.append(("TP", f"svc{i}.example.com", "CVE-2024-1000", src, f"HTTP 200 proof on svc{i} via {src}", True, 0.90))
            # 10 FPs (second check fails)
            for i in range(10):
                raw_findings.append(("FP", f"svc{i}.example.com", "fp-banner-match", "nuclei", "banner=nginx generic", False, 0.70))
            # 10 empty-evidence noise
            for i in range(10):
                raw_findings.append(("NOISE", f"svc{i}.example.com", "empty-alert", "legacy", "", None, 0.40))

            persisted_ok = 0
            verified_confirmed = 0
            with_evidence = 0
            fp_emitted_as_confirmed_or_probable = 0
            tp_accepted = 0

            for kind, host, title, src, ev_text, second_ok, conf in raw_findings:
                cand = CandidateFinding(
                    finding_id=f"F-{len(afp.decision_log)+1}",
                    organization_id=1,
                    asset=host,
                    title=title,
                    severity="HIGH" if kind == "TP" else "MEDIUM",
                    source=src,
                    raw_evidence=ev_text,
                    detection_method="controlled_eval",
                    confidence=conf,
                    second_check_passed=second_ok,
                )
                afp_res = afp.process_finding(cand)
                if afp_res.get("deduplicated"):
                    continue

                state = afp_res["state"]
                if state in (FindingValidationState.CONFIRMADO.value, FindingValidationState.PROBABLE.value):
                    if kind == "TP":
                        tp_accepted += 1
                    else:
                        fp_emitted_as_confirmed_or_probable += 1

                if state == FindingValidationState.CONFIRMADO.value:
                    verified_confirmed += 1

                nf = NormalizedFinding(
                    organization_id=1,
                    entity_type="subdomain",
                    entity_value=host,
                    finding_type="vulnerability",
                    source=src,
                    severity=cand.severity,
                    confidence=conf,
                    verification_status=state,
                    evidence=ev_text,
                    canonical_key=title,
                )
                dedup.ingest(nf)
                if nf.evidence:
                    with_evidence += 1
                ev_mgr.record_finding(
                    organization_id=1,
                    related_asset=host,
                    source=src,
                    technical_evidence=ev_text or "no-evidence",
                    detection_method="controlled_eval",
                    confidence_level=conf,
                )
                persisted_ok += 1

            db.commit()
            persisted_in_db = db.query(EvidenceRecord).filter(EvidenceRecord.organization_id == 1).count()

            cpu_elapsed = time.process_time() - t_cpu_0
            wall_elapsed = time.perf_counter() - t_wall_0
            _curr_mem, peak_mem_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            # Provider error rate with Circuit Breaker (10 calls to failing provider -> 3 errors + 7 short-circuited)
            svc = DomainIntelligenceService.__new__(DomainIntelligenceService)
            DomainIntelligenceService._circuit_failures.clear()
            DomainIntelligenceService._circuit_open_until.clear()

            async def _fail_coro():
                return ProviderResponse(provider_name="broken_api", status=ProviderQueryStatus.CONNECTION_ERROR, error_message="503")

            network_attempts = 0
            for _ in range(10):
                r = await svc._run_limited("broken_api", _fail_coro())
                if "Circuit breaker OPEN" not in (r.error_message or ""):
                    network_attempts += 1

            db.close()
            sql_engine.dispose()

            total_accepted = tp_accepted + fp_emitted_as_confirmed_or_probable
            precision = tp_accepted / total_accepted if total_accepted else 0.0
            fp_rate = fp_emitted_as_confirmed_or_probable / total_accepted if total_accepted else 0.0
            unique_count = len(dedup.all_findings())

            print(
                f"\n[FASE5_METRICS] asset_coverage={asset_coverage:.2%} wildcard_fp={wildcard_fp_rate:.2%} "
                f"precision={precision:.2%} fp_rate={fp_rate:.2%} dedup_unique={unique_count}/40 "
                f"with_evidence={with_evidence}/{persisted_ok} verified={verified_confirmed}/{persisted_ok} "
                f"persisted={persisted_in_db}/{persisted_ok} wall_s={wall_elapsed:.4f} cpu_s={cpu_elapsed:.4f} "
                f"peak_ram_kb={peak_mem_bytes/1024:.1f} cb_network_attempts={network_attempts}/10"
            )

            self.assertEqual(asset_coverage, 1.0)
            self.assertEqual(wildcard_fp_rate, 0.0)
            self.assertEqual(precision, 1.0)
            self.assertEqual(fp_rate, 0.0)
            self.assertEqual(persisted_in_db, persisted_ok)
            self.assertEqual(network_attempts, 3)
        finally:
            if os.path.exists(db_file):
                os.remove(db_file)


if __name__ == "__main__":
    unittest.main()
