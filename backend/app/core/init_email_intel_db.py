"""
Database Initializer and Migrator for the EMAIL INTELLIGENCE module.
Ensures that all 7 email intelligence tables and indexes exist in:
1. Operational SQLite database (web_dashboard/openrecon.sqlite).
2. Backend SQLAlchemy database (openrecon.db / engine).
Guarantees zero downtime and zero disruption to the existing 33 OpenRecon tables.
"""

import sqlite3
import os
import logging
from sqlalchemy import text
from app.core.database import engine, Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("email_intel.init_db")

def resolve_sqlite_path() -> str:
    candidates = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "web_dashboard", "openrecon.sqlite")),
        os.path.abspath(os.path.join(os.getcwd(), "web_dashboard", "openrecon.sqlite")),
        os.path.abspath(os.path.join(os.getcwd(), "openrecon.sqlite")),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[0]

SQLITE_PATH = resolve_sqlite_path()

EMAIL_INTEL_DDL_SQLITE = """
-- 1. Investigations Table
CREATE TABLE IF NOT EXISTS email_intel_investigations (
    id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    target_email VARCHAR(255) NOT NULL,
    description TEXT,
    tags TEXT,
    authorization_justification TEXT NOT NULL,
    status VARCHAR(30) DEFAULT 'PENDING',
    progress INTEGER DEFAULT 0,
    exposure_score REAL DEFAULT 0.0,
    risk_level VARCHAR(20) DEFAULT 'INFORMATIVE',
    risk_explanation TEXT,
    total_findings INTEGER DEFAULT 0,
    created_by VARCHAR(100) DEFAULT 'analyst',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_email_intel_inv_email ON email_intel_investigations (target_email);
CREATE INDEX IF NOT EXISTS idx_email_intel_inv_case ON email_intel_investigations (case_id);
CREATE INDEX IF NOT EXISTS idx_email_intel_inv_status ON email_intel_investigations (status);
CREATE INDEX IF NOT EXISTS idx_email_intel_inv_created ON email_intel_investigations (created_at);

-- 2. Evidence Vault (DFIR Immutable Evidence)
CREATE TABLE IF NOT EXISTS email_intel_evidence (
    id VARCHAR(64) PRIMARY KEY,
    investigation_id VARCHAR(64) NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    source_name VARCHAR(100) NOT NULL,
    collected_at_utc DATETIME NOT NULL,
    raw_content_preview TEXT NOT NULL,
    content_sha256 VARCHAR(64) NOT NULL,
    custody_signature VARCHAR(128) NOT NULL,
    validation_status VARCHAR(30) DEFAULT 'DETECTED',
    confidence_score REAL DEFAULT 0.5,
    FOREIGN KEY(investigation_id) REFERENCES email_intel_investigations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_email_intel_ev_inv ON email_intel_evidence (investigation_id);
CREATE INDEX IF NOT EXISTS idx_email_intel_ev_sha ON email_intel_evidence (content_sha256);

-- 3. Leaks Table (Strict K-Anonymity, ZERO plaintext passwords)
CREATE TABLE IF NOT EXISTS email_intel_leaks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id VARCHAR(64) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    source VARCHAR(100) NOT NULL,
    leak_date VARCHAR(50),
    query_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    exposed_data_types TEXT NOT NULL,
    confidence_level VARCHAR(20) DEFAULT 'HIGH',
    verifiable_reference TEXT,
    corporate_services_count INTEGER DEFAULT 0,
    user_services_count INTEGER DEFAULT 0,
    computer_name_preview VARCHAR(100),
    operating_system VARCHAR(100),
    ip_address_preview VARCHAR(50),
    FOREIGN KEY(investigation_id) REFERENCES email_intel_investigations(id) ON DELETE CASCADE,
    FOREIGN KEY(evidence_id) REFERENCES email_intel_evidence(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_email_intel_leaks_inv ON email_intel_leaks (investigation_id);

-- 4. Accounts Table (Presence in Digital Services)
CREATE TABLE IF NOT EXISTS email_intel_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id VARCHAR(64) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    platform VARCHAR(100) NOT NULL,
    status VARCHAR(30) NOT NULL, -- 'CONFIRMED', 'PROBABLE', 'NOT_FOUND', 'INCONCLUSIVE', 'QUERY_ERROR'
    query_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    check_method VARCHAR(100) NOT NULL,
    evidence_snippet TEXT,
    profile_url TEXT,
    avatar_url TEXT,
    username VARCHAR(150),
    confidence_level VARCHAR(20) DEFAULT 'HIGH',
    FOREIGN KEY(investigation_id) REFERENCES email_intel_investigations(id) ON DELETE CASCADE,
    FOREIGN KEY(evidence_id) REFERENCES email_intel_evidence(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_email_intel_acc_inv ON email_intel_accounts (investigation_id);
CREATE INDEX IF NOT EXISTS idx_email_intel_acc_platform ON email_intel_accounts (platform);
CREATE INDEX IF NOT EXISTS idx_email_intel_acc_status ON email_intel_accounts (status);

-- 5. Pastes Table
CREATE TABLE IF NOT EXISTS email_intel_pastes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id VARCHAR(64) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    source VARCHAR(100) NOT NULL,
    paste_url TEXT NOT NULL,
    discovered_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    minimal_context TEXT,
    classification VARCHAR(50) DEFAULT 'PUBLIC_TEXT',
    evidence_snippet TEXT,
    FOREIGN KEY(investigation_id) REFERENCES email_intel_investigations(id) ON DELETE CASCADE,
    FOREIGN KEY(evidence_id) REFERENCES email_intel_evidence(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_email_intel_pastes_inv ON email_intel_pastes (investigation_id);

-- 6. Domain & DNS Intelligence
CREATE TABLE IF NOT EXISTS email_intel_domain_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id VARCHAR(64) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    mail_provider VARCHAR(150),
    mx_records_json TEXT,
    spf_record TEXT,
    spf_status VARCHAR(50),
    dmarc_record TEXT,
    dmarc_status VARCHAR(50),
    dkim_status VARCHAR(50),
    dns_security_score INTEGER DEFAULT 0,
    weaknesses_json TEXT,
    recommendations_json TEXT,
    analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(investigation_id) REFERENCES email_intel_investigations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_email_intel_domain_inv ON email_intel_domain_analysis (investigation_id);

-- 7. Email Generated Variants (Hypotheses)
CREATE TABLE IF NOT EXISTS email_intel_generated_variants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id VARCHAR(64) NOT NULL,
    base_email VARCHAR(255) NOT NULL,
    variant_email VARCHAR(255) NOT NULL,
    domain_type VARCHAR(50) NOT NULL,
    pattern_type VARCHAR(50) NOT NULL,
    classification VARCHAR(50) DEFAULT 'HYPOTHESIS_UNVERIFIED',
    passive_mx_valid BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(investigation_id) REFERENCES email_intel_investigations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_email_intel_variants_inv ON email_intel_generated_variants (investigation_id);
"""


def init_sqlite_db():
    """Initializes operational SQLite database at web_dashboard/openrecon.sqlite."""
    logger.info(f"Connecting to operational SQLite DB: {SQLITE_PATH}")
    if not os.path.exists(SQLITE_PATH):
        logger.warning(f"Database file does not exist at {SQLITE_PATH}, creating fresh.")

    conn = sqlite3.connect(SQLITE_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        conn.executescript(EMAIL_INTEL_DDL_SQLITE)
        conn.commit()
        logger.info("Email Intelligence SQLite tables and indexes successfully created or updated.")
    except Exception as e:
        logger.error(f"Error initializing Email Intelligence SQLite tables: {e}")
        conn.rollback()
        raise e
    finally:
        conn.close()


def init_sqlalchemy_db():
    """Initializes SQLAlchemy database (openrecon.db / Postgres)."""
    logger.info("Initializing SQLAlchemy models for Email Intelligence.")
    try:
        with engine.begin() as conn:
            for statement in EMAIL_INTEL_DDL_SQLITE.split(";"):
                stmt = statement.strip()
                if stmt:
                    conn.execute(text(stmt))
        logger.info("Email Intelligence SQLAlchemy tables initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing SQLAlchemy DB: {e}")
        raise e


def init_all():
    init_sqlite_db()
    init_sqlalchemy_db()


if __name__ == "__main__":
    init_all()
