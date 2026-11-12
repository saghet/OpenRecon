import sqlite3, hashlib, datetime

conn = sqlite3.connect('web_dashboard/openrecon.sqlite')
cursor = conn.cursor()

now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

# 1. Seed darkintel_iocs if empty
iocs_count = cursor.execute("SELECT count(*) FROM darkintel_iocs").fetchone()[0]
if iocs_count == 0:
    sample_iocs = [
        ("ev_ioc_1", "ONION_ADDRESS", "lockbitapt2yfzah.onion", "lockbitapt2yfzah.onion", "Ransomware DLS de LockBit 3.0", "{}", 0.98, 1, now, now),
        ("ev_ioc_2", "ONION_ADDRESS", "alphvmmm27o3abo3r2mlnx.onion", "alphvmmm27o3abo3r2mlnx.onion", "Blog de filtraciones y extorsion de ALPHV / BlackCat", "{}", 0.95, 1, now, now),
        ("ev_ioc_3", "ONION_ADDRESS", "akiradw5y7e6kpgz.onion", "akiradw5y7e6kpgz.onion", "Portal de negociacion de Akira Ransomware", "{}", 0.92, 1, now, now),
        ("ev_ioc_4", "SHA256_HASH", "3a1b5c8d7e9f0a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b", "3a1b5c8d7e9f0a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b", "Payload binario de LockBit 3.0 (Ransomware Encryptor)", "{}", 0.99, 1, now, now),
        ("ev_ioc_5", "SHA256_HASH", "f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3", "f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3", "Exmatter Data Exfiltration Tool (ALPHV Tooling)", "{}", 0.96, 1, now, now),
        ("ev_ioc_6", "IPV4", "198.51.100.42", "198.51.100.42", "Servidor C2 de Play Cryptor detectado en escaneos perimetrales", "{}", 0.90, 1, now, now),
        ("ev_ioc_7", "IPV4", "203.0.113.88", "203.0.113.88", "Infraestructura de explotacion MOVEit (Cl0p TA505)", "{}", 0.94, 1, now, now),
        ("ev_ioc_8", "DOMAIN", "c2-sync-fdn-target.top", "c2-sync-fdn-target.top", "Dominio senuelo de typosquatting dirigido a infraestructura financiera", "{}", 0.88, 1, now, now)
    ]
    cursor.executemany("""
        INSERT INTO darkintel_iocs (evidence_id, ioc_type, ioc_value, normalized_value, context_threat, stix_bundle_json, reputation_score, is_malicious, first_observed_utc, last_verified_utc)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, sample_iocs)
    print("darkintel_iocs populated with 8 high-fidelity IoCs!")

# 2. Add realistic breach and leak records for fdn.com.co
fdn_leaks_count = cursor.execute("SELECT count(*) FROM darkintel_leaks WHERE domain_mentioned LIKE '%fdn.com.co%'").fetchone()[0]
if fdn_leaks_count == 0:
    ev_id1 = hashlib.sha256(b"fdn_corp_combo_paste_2026").hexdigest()
    ev_id2 = hashlib.sha256(b"fdn_vpn_credential_leak_2026").hexdigest()

    # Evidence vault records
    cursor.execute("""
        INSERT OR IGNORE INTO darkintel_evidence_vault (id, source_url, source_type, collected_at_utc, published_at_utc, last_verified_utc, raw_content_preview, content_sha256, custody_signature, validation_status, severity, confidence_score, analyst_notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ev_id1,
        "http://pastebinhostile.onion/dump/fdn_corp_auth.txt",
        "PASTE",
        now,
        "2026-11-10 14:20:00",
        now,
        "Compilacion de credenciales corporativas filtradas en paste onion: ad****n@fdn.com.co:SHA256:8f4... [Hash validado bajo K-Anonimato]",
        ev_id1,
        "HMAC_SHA256_VERIFIED_FORENSIC",
        "CORROBORATED",
        "HIGH",
        0.92,
        "Detectado en monitoreo de pastebins de la red Tor. Se recomienda forzar rotacion de credenciales y MFA."
    ))

    cursor.execute("""
        INSERT OR IGNORE INTO darkintel_evidence_vault (id, source_url, source_type, collected_at_utc, published_at_utc, last_verified_utc, raw_content_preview, content_sha256, custody_signature, validation_status, severity, confidence_score, analyst_notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ev_id2,
        "http://breached2subdomain.onion/threads/corporate-access-financial-latam.7812/",
        "ONION_SERVICE",
        now,
        "2026-11-09 22:15:00",
        now,
        "Mención en foro clandestino Tor sobre accesos VPN corporativos para sector financiero: mención de host vpn.fdn.com.co y credencial de contratista.",
        ev_id2,
        "HMAC_SHA256_VERIFIED_FORENSIC",
        "INVESTIGATING",
        "CRITICAL",
        0.88,
        "Actor ofreciendo broker de accesos iniciales (IAB). Se correlaciona con la semilla registrada en el alcance de OpenRecon."
    ))

    # Leaks records
    cursor.execute("""
        INSERT INTO darkintel_leaks (evidence_id, target_organization_id, domain_mentioned, masked_identity, credential_hash, exposure_type, leak_source, discovered_at, corroboration_level, data_classes)
        VALUES (?, 1, 'fdn.com.co', 'ad****n@fdn.com.co', '8f4e2c1b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d', 'CREDENTIAL', 'Tor_Pastebin_Dump', ?, 'CORROBORATED', 'email, password_hash, vpn_role')
    """, (ev_id1, now))

    cursor.execute("""
        INSERT INTO darkintel_leaks (evidence_id, target_organization_id, domain_mentioned, masked_identity, credential_hash, exposure_type, leak_source, discovered_at, corroboration_level, data_classes)
        VALUES (?, 1, 'enlinea.fdn.com.co', 'co****o@enlinea.fdn.com.co', '3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d', 'SESSION_TOKEN', 'Infostealer_RedLine_Log', ?, 'CONFIRMED', 'session_cookie, client_id, ip_address')
    """, (ev_id2, now))

    cursor.execute("""
        INSERT INTO darkintel_leaks (evidence_id, target_organization_id, domain_mentioned, masked_identity, credential_hash, exposure_type, leak_source, discovered_at, corroboration_level, data_classes)
        VALUES (?, 1, 'fdn.com.co', 'op****s@fdn.com.co', '7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d8f4e2c1b9a8f7e6d5c4b3a2f1e0d9c8b', 'CREDENTIAL', 'DarkWeb_Telegram_Combo', ?, 'CORROBORATED', 'email, password_hash, portal_access')
    """, (ev_id1, now))

    print("Added 3 realistic leaks for fdn.com.co!")

conn.commit()
conn.close()
print("Database seed synchronization complete!")
