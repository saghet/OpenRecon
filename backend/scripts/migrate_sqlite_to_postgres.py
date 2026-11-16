"""
Progressive SQLite -> PostgreSQL Data Migrator for OpenRecon 3.0.
Safely migrates Email Intelligence, Dark Intelligence, and core EASM records
from web_dashboard/openrecon.sqlite into PostgreSQL without losing data or duplicating PKs.
"""

import argparse
import logging
import os
import sqlite3
from typing import List

from sqlalchemy import create_engine, inspect, text

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("openrecon.sqlite_to_pg")

TABLES_IN_ORDER: List[str] = [
    "organizations",
    "seeds",
    "assets",
    "port_services",
    "vulnerabilities",
    "digital_risk_findings",
    "scan_jobs",
    "evidence_records",
    "evidence_audit_logs",
    "email_intel_investigations",
    "email_intel_evidence",
    "email_intel_leaks",
    "email_intel_accounts",
    "email_intel_pastes",
    "email_intel_domain_analysis",
    "email_intel_generated_variants",
    "darkintel_evidence_vault",
    "darkintel_sources",
    "darkintel_leaks",
    "darkintel_ransomware_posts",
    "darkintel_threat_actors",
    "darkintel_iocs",
    "darkintel_search_queries",
    "darkintel_investigations",
]


def migrate(sqlite_path: str, pg_url: str, dry_run: bool = False) -> dict:
    if not os.path.exists(sqlite_path):
        raise FileNotFoundError(f"SQLite file not found: {sqlite_path}")

    if pg_url.startswith("postgresql://"):
        pg_url = "postgresql+psycopg2://" + pg_url[len("postgresql://"):]

    src_conn = sqlite3.connect(sqlite_path)
    src_conn.row_factory = sqlite3.Row
    dst_engine = create_engine(pg_url)
    dst_tables = set(inspect(dst_engine).get_table_names())

    report = {}
    with dst_engine.begin() as dst_conn:
        for table in TABLES_IN_ORDER:
            src_exists = src_conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if not src_exists or table not in dst_tables:
                continue

            rows = src_conn.execute(f"SELECT * FROM {table}").fetchall()
            if not rows:
                report[table] = 0
                continue

            cols = list(rows[0].keys())
            col_list = ", ".join(cols)
            param_list = ", ".join(f":{c}" for c in cols)
            stmt = text(f"INSERT INTO {table} ({col_list}) VALUES ({param_list}) ON CONFLICT DO NOTHING")

            if not dry_run:
                for r in rows:
                    dst_conn.execute(stmt, dict(r))
            report[table] = len(rows)
            logger.info(f"Table '{table}': {len(rows)} rows {'(dry-run)' if dry_run else 'migrated'}.")

    src_conn.close()
    dst_engine.dispose()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate OpenRecon SQLite data to PostgreSQL.")
    parser.add_argument("--sqlite", default="web_dashboard/openrecon.sqlite")
    parser.add_argument("--postgres", default=os.getenv("DATABASE_URL", ""))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not args.postgres:
        raise SystemExit("Error: --postgres or DATABASE_URL is required.")
    migrate(args.sqlite, args.postgres, dry_run=args.dry_run)
