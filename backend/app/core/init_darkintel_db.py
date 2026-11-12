"""
Database Initializer and Migrator for the DARK INTELLIGENCE module.
Ensures that all 8 dark intelligence tables and indexes exist in:
1. Operational SQLite database (web_dashboard/openrecon.sqlite).
2. Backend SQLAlchemy database (engine).
Guarantees zero downtime and zero disruption to the existing 25 OpenRecon tables.
"""

import sqlite3
import os
import logging
from sqlalchemy import text
from app.core.database import engine, Base
import app.models  # Ensures all models (core + darkintel) are loaded

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("darkintel.init_db")

SQLITE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "web_dashboard", "openrecon.sqlite")
)

DARKINTEL_DDL_SQLITE = """
-- 1. Evidence Vault
CREATE TABLE IF NOT EXISTS darkintel_evidence_vault (
    id VARCHAR(64) PRIMARY KEY,
    source_url TEXT NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    collected_at_utc DATETIME NOT NULL,
    published_at_utc DATETIME,
    last_verified_utc DATETIME,
    raw_content_preview TEXT NOT NULL,
    content_sha256 VARCHAR(64) NOT NULL,
    custody_signature VARCHAR(128) NOT NULL,
    validation_status VARCHAR(30) DEFAULT 'DETECTED',
    severity VARCHAR(20) DEFAULT 'MEDIUM',
    confidence_score REAL DEFAULT 0.5,
    analyst_notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_darkintel_vault_sha256 ON darkintel_evidence_vault (content_sha256);
CREATE INDEX IF NOT EXISTS idx_darkintel_vault_status ON darkintel_evidence_vault (validation_status);
CREATE INDEX IF NOT EXISTS idx_darkintel_vault_severity ON darkintel_evidence_vault (severity);

-- 2. Dark Web Sources & Onion Tracking
CREATE TABLE IF NOT EXISTS darkintel_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name VARCHAR(150) NOT NULL,
    onion_address VARCHAR(255) NOT NULL UNIQUE,
    category VARCHAR(50) DEFAULT 'RANSOMWARE_DLS',
    status VARCHAR(20) DEFAULT 'ACTIVE',
    reliability_rating VARCHAR(10) DEFAULT 'B',
    last_seen_online DATETIME,
    response_time_ms INTEGER,
    check_interval_mins INTEGER DEFAULT 360,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_darkintel_sources_onion ON darkintel_sources (onion_address);
CREATE INDEX IF NOT EXISTS idx_darkintel_sources_status ON darkintel_sources (status);

-- 3. Leaks & Compromised Identities
CREATE TABLE IF NOT EXISTS darkintel_leaks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id VARCHAR(64) NOT NULL,
    target_organization_id INTEGER,
    domain_mentioned VARCHAR(255) NOT NULL,
    masked_identity VARCHAR(255) NOT NULL,
    credential_hash VARCHAR(64),
    exposure_type VARCHAR(50) DEFAULT 'CREDENTIAL',
    leak_source VARCHAR(100) NOT NULL,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    corroboration_level VARCHAR(30) DEFAULT 'UNVERIFIED',
    data_classes TEXT,
    FOREIGN KEY(evidence_id) REFERENCES darkintel_evidence_vault(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_darkintel_leaks_domain ON darkintel_leaks (domain_mentioned);
CREATE INDEX IF NOT EXISTS idx_darkintel_leaks_evidence ON darkintel_leaks (evidence_id);
CREATE INDEX IF NOT EXISTS idx_darkintel_leaks_cred_hash ON darkintel_leaks (credential_hash);

-- 4. Ransomware Extortion Intelligence
CREATE TABLE IF NOT EXISTS darkintel_ransomware_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id VARCHAR(64) NOT NULL,
    group_name VARCHAR(100) NOT NULL,
    victim_name VARCHAR(255) NOT NULL,
    victim_website VARCHAR(255),
    claim_details TEXT,
    ransom_deadline DATETIME,
    data_volume_gb REAL,
    matched_organization_id INTEGER,
    post_date_utc DATETIME,
    discovered_at_utc DATETIME DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'ACTIVE',
    proof_links TEXT,
    FOREIGN KEY(evidence_id) REFERENCES darkintel_evidence_vault(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_darkintel_ransom_group ON darkintel_ransomware_posts (group_name);
CREATE INDEX IF NOT EXISTS idx_darkintel_ransom_victim ON darkintel_ransomware_posts (victim_name);
CREATE INDEX IF NOT EXISTS idx_darkintel_ransom_website ON darkintel_ransomware_posts (victim_website);

-- 5. Threat Actor Intelligence
CREATE TABLE IF NOT EXISTS darkintel_threat_actors (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(150) NOT NULL UNIQUE,
    aliases TEXT,
    origin_country VARCHAR(10),
    motivation VARCHAR(50) DEFAULT 'FINANCIAL',
    associated_malware TEXT,
    mitre_techniques TEXT,
    darkweb_dls_onion VARCHAR(255),
    target_sectors TEXT,
    confidence_level VARCHAR(20) DEFAULT 'MEDIUM',
    last_activity_date DATETIME
);
CREATE INDEX IF NOT EXISTS idx_darkintel_actors_name ON darkintel_threat_actors (name);

-- 6. IOC Intelligence & STIX 2.1 Indicators
CREATE TABLE IF NOT EXISTS darkintel_iocs (
    id VARCHAR(64) PRIMARY KEY,
    evidence_id VARCHAR(64) NOT NULL,
    ioc_type VARCHAR(30) NOT NULL,
    ioc_value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    context_threat VARCHAR(150),
    stix_bundle_json TEXT,
    reputation_score INTEGER DEFAULT 0,
    is_malicious BOOLEAN DEFAULT 0,
    first_observed_utc DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_verified_utc DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(evidence_id) REFERENCES darkintel_evidence_vault(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_darkintel_iocs_normalized ON darkintel_iocs (normalized_value);
CREATE INDEX IF NOT EXISTS idx_darkintel_iocs_type ON darkintel_iocs (ioc_type);

-- 7. Search Auditing & Coverage Transparency
CREATE TABLE IF NOT EXISTS darkintel_search_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query_string TEXT NOT NULL,
    query_type VARCHAR(50) DEFAULT 'DOMAIN',
    filters_applied TEXT,
    sources_queried TEXT NOT NULL,
    results_count INTEGER DEFAULT 0,
    onion_results_count INTEGER DEFAULT 0,
    executed_by VARCHAR(100) DEFAULT 'analyst',
    executed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_darkintel_search_executed ON darkintel_search_queries (executed_at);

-- 8. Organization Exposure Investigations
CREATE TABLE IF NOT EXISTS darkintel_investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    title VARCHAR(255) NOT NULL,
    investigation_scope TEXT NOT NULL,
    status VARCHAR(30) DEFAULT 'PENDING',
    total_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    exposure_score REAL DEFAULT 0.0,
    executive_summary TEXT,
    recommendations TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_darkintel_invest_org ON darkintel_investigations (organization_id);
"""


def init_sqlite_db(db_path: str = SQLITE_PATH) -> bool:
    """
    Applies Dark Intelligence DDL directly to the SQLite database.
    """
    if not os.path.exists(db_path):
        logger.warning(f"Target SQLite DB does not exist at {db_path}; creating new.")

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.executescript(DARKINTEL_DDL_SQLITE)
        conn.commit()
        logger.info(f"Successfully migrated SQLite DB at: {db_path}")
        return True
    except Exception as e:
        logger.error(f"Error migrating SQLite DB: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


def init_sqlalchemy_db() -> bool:
    """
    Applies SQLAlchemy metadata to backend engine (supporting Postgres / backend SQLite).
    """
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Successfully created SQLAlchemy tables via engine metadata.")
        return True
    except Exception as e:
        logger.error(f"Error creating SQLAlchemy tables: {e}")
        raise


if __name__ == "__main__":
    logger.info("Initializing Dark Intelligence tables...")
    init_sqlite_db()
    init_sqlalchemy_db()
    logger.info("Initialization completed successfully.")
