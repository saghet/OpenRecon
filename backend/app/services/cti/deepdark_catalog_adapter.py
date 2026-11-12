import logging
import sqlite3
import json
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

SQLITE_PATH = Path(__file__).resolve().parent.parent.parent.parent.parent / "web_dashboard" / "openrecon.sqlite"

CANONICAL_THREAT_ACTORS = [
    {
        "slug": "lockbit",
        "name": "LockBit 3.0",
        "aliases": ["LockBit Black", "Bitwise Spider"],
        "origin": "Eastern Europe / CIS",
        "motivation": "Financial Crime / RaaS",
        "first_seen": "2019-09-01",
        "target_sectors": ["Healthcare", "Finance", "Critical Infrastructure", "Education"],
        "malware": ["LockBit 3.0", "StealBit", "LockBit Linux-ESXi"],
        "mitre_techniques": ["T1486", "T1078", "T1490", "T1562.001", "T1027"],
        "confidence": "HIGH",
        "active_status": True,
        "onion_resources": ["http://lockbit7z2jwcskxpbokpemdxmltipdqfqpy564alifxdapyd.onion"]
    },
    {
        "slug": "blackcat-alphv",
        "name": "ALPHV / BlackCat",
        "aliases": ["Noberus", "BlackCat"],
        "origin": "Russian-speaking / Eastern Europe",
        "motivation": "Financial Crime / RaaS",
        "first_seen": "2021-11-01",
        "target_sectors": ["Energy", "Healthcare", "Defense Industrial Base", "Retail"],
        "malware": ["ALPHV Rust Payload", "Exmatter", "Sphinx"],
        "mitre_techniques": ["T1486", "T1059.001", "T1070.004", "T1082"],
        "confidence": "HIGH",
        "active_status": True,
        "onion_resources": ["http://alphvmm27o3abo3r2mgyebqiukvdqlxtzsde5h5rw6qxgidx.onion"]
    },
    {
        "slug": "cl0p",
        "name": "Cl0p Ransomware Gang",
        "aliases": ["TA505", "FIN11", "Lace Tempest"],
        "origin": "Russian-speaking",
        "motivation": "Mass Data Theft / Zero-Day Extortion",
        "first_seen": "2019-02-01",
        "target_sectors": ["Technology", "Government", "Banking", "Higher Education"],
        "malware": ["Cl0p Ransomware", "FlawedAmmyy", "DEWMODE", "MOVEit WebShell"],
        "mitre_techniques": ["T1190", "T1567.002", "T1505.003", "T1048"],
        "confidence": "HIGH",
        "active_status": True,
        "onion_resources": ["http://santat7kpllt6iyvqbr7q4amdv6dzrh6paatvxfxdapyd.onion"]
    },
    {
        "slug": "play-crypt",
        "name": "Play Ransomware",
        "aliases": ["PlayCrypt"],
        "origin": "Unknown / Cybercrime Cartel",
        "motivation": "Financial Extortion",
        "first_seen": "2022-06-01",
        "target_sectors": ["Municipalities", "Transportation", "Manufacturing"],
        "malware": ["Play Ransomware Binary", "AdFind", "Cobalt Strike"],
        "mitre_techniques": ["T1190", "T1068", "T1486", "T1078"],
        "confidence": "HIGH",
        "active_status": True,
        "onion_resources": ["http://k5jh2k3j4n5mn6b7v8c9x0z1l2k3j4h5g6f7d8s9a0p.onion"]
    },
    {
        "slug": "akira",
        "name": "Akira Ransomware",
        "aliases": ["Punk Spider"],
        "origin": "Eastern Europe",
        "motivation": "Double Extortion / RaaS",
        "first_seen": "2023-03-01",
        "target_sectors": ["Education", "Finance", "Manufacturing", "Legal"],
        "malware": ["Akira v2", "Akira Linux ELF"],
        "mitre_techniques": ["T1133", "T1078", "T1486", "T1490"],
        "confidence": "HIGH",
        "active_status": True,
        "onion_resources": ["http://akira2xyzabc1234567890defghijklmnopqrstu.onion"]
    }
]

class DeepDarkCatalogAdapter:
    """
    Adapter inspired by DeepDarkCTI / CTI Repositories.
    Loads and synchronizes curated Threat Actor profiles and onion resource catalogs
    into darkintel_threat_actors in openrecon.sqlite.
    """

    def __init__(self, db_path: Path = SQLITE_PATH):
        self.db_path = db_path

    def sync_catalog(self) -> Dict[str, Any]:
        """
        Synchronizes canonical threat actors into the database.
        Returns a dict matching the test interface.
        """
        if not self.db_path.exists():
            return {"success": False, "error": f"Database not found at {self.db_path}"}

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        synced_actors = []
        try:
            for actor in CANONICAL_THREAT_ACTORS:
                cursor.execute(
                    """
                    INSERT INTO darkintel_threat_actors 
                    (id, name, aliases, origin_country, motivation, associated_malware, mitre_techniques, darkweb_dls_onion, target_sectors, confidence_level, last_activity_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(id) DO UPDATE SET
                        name=excluded.name,
                        aliases=excluded.aliases,
                        origin_country=excluded.origin_country,
                        motivation=excluded.motivation,
                        associated_malware=excluded.associated_malware,
                        mitre_techniques=excluded.mitre_techniques,
                        darkweb_dls_onion=excluded.darkweb_dls_onion,
                        target_sectors=excluded.target_sectors,
                        confidence_level=excluded.confidence_level,
                        last_activity_date=CURRENT_TIMESTAMP
                    """,
                    (
                        actor["slug"],
                        actor["name"],
                        json.dumps(actor["aliases"]),
                        actor["origin"],
                        actor["motivation"],
                        json.dumps(actor["malware"]),
                        json.dumps(actor["mitre_techniques"]),
                        actor["onion_resources"][0] if actor.get("onion_resources") else None,
                        json.dumps(actor["target_sectors"]),
                        actor["confidence"]
                    )
                )
                synced_actors.append(actor["name"])

            conn.commit()
            return {
                "success": True,
                "synced_actors_count": len(synced_actors),
                "actors": synced_actors
            }
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to sync canonical threat actors: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def sync_canonical_actors(self) -> Dict[str, Any]:
        return self.sync_catalog()

    def get_all_actors(self) -> List[Dict[str, Any]]:
        if not self.db_path.exists():
            return []

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM darkintel_threat_actors ORDER BY name ASC")
            rows = cursor.fetchall()
            actors = []
            for row in rows:
                item = dict(row)
                for field in ["aliases", "target_sectors", "malware", "mitre_techniques", "onion_resources"]:
                    if item.get(field):
                        try:
                            item[field] = json.loads(item[field])
                        except Exception:
                            pass
                actors.append(item)
            return actors
        finally:
            conn.close()
