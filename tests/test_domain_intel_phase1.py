import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.core.domain_security import (
    CredentialVault,
    DomainSecurityError,
    check_ip_is_public,
    enforce_anti_ssrf_and_dns_rebinding,
    validate_and_normalize_indicator,
)
from app.models.organization import Organization
from app.models.domain_intel import (
    DomainInvestigation,
    DomainProviderResult,
    DomainIndicator,
    DomainReputationHistory,
    ProviderCredential,
    IndicatorInputType,
    ProviderQueryStatus,
    DomainRiskTier,
)


class TestDomainIntelPhase1(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_indicator_detection_and_normalization(self):
        res_dom = validate_and_normalize_indicator("Example.COM.")
        self.assertEqual(res_dom["input_type"], IndicatorInputType.DOMAIN)
        self.assertEqual(res_dom["normalized_domain"], "example.com")

        res_sub = validate_and_normalize_indicator("api.example.com")
        self.assertEqual(res_sub["input_type"], IndicatorInputType.SUBDOMAIN)
        self.assertEqual(res_sub["registered_domain"], "example.com")

        res_ip4 = validate_and_normalize_indicator("8.8.8.8")
        self.assertEqual(res_ip4["input_type"], IndicatorInputType.IPV4)

        res_ip6 = validate_and_normalize_indicator("2001:4860:4860::8888")
        self.assertEqual(res_ip6["input_type"], IndicatorInputType.IPV6)

        res_url = validate_and_normalize_indicator("https://portal.example.org/login")
        self.assertEqual(res_url["input_type"], IndicatorInputType.URL)
        self.assertEqual(res_url["normalized_domain"], "portal.example.org")

    def test_ssrf_and_input_validation_blocks(self):
        blocked_inputs = [
            "",
            "127.0.0.1",
            "10.10.1.5",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "localhost",
            "metadata.google.internal",
            "intranet.local",
            "http://127.0.0.1:8000/admin",
            "http://user:pass@example.com",
            "file:///etc/passwd",
            "https://example.com/../../etc/passwd",
            "example.com;rm -rf /",
        ]
        for bad in blocked_inputs:
            with self.subTest(bad=bad):
                with self.assertRaises(DomainSecurityError):
                    validate_and_normalize_indicator(bad)

    def test_dns_rebinding_protection_blocks_private_resolution(self):
        fake_addr = [(2, 1, 6, "", ("127.0.0.1", 0))]
        with patch("app.core.domain_security.socket.getaddrinfo", return_value=fake_addr):
            with self.assertRaises(DomainSecurityError):
                enforce_anti_ssrf_and_dns_rebinding("rebind.attacker.example", resolve_dns=True)

    def test_credential_vault_encryption_and_masking(self):
        secret = "vt_super_secret_api_key_987654321"
        encrypted = CredentialVault.encrypt_key(secret)
        self.assertNotIn(secret, encrypted)
        self.assertEqual(CredentialVault.decrypt_key(encrypted), secret)
        self.assertEqual(CredentialVault.mask_key(secret), "vt_s...4321")

    def test_sqlalchemy_models_persistence(self):
        org = Organization(name="Org Test DomainIntel")
        self.db.add(org)
        self.db.commit()
        self.db.refresh(org)

        cred = ProviderCredential(
            organization_id=org.id,
            provider_name="virustotal",
            encrypted_api_key=CredentialVault.encrypt_key("vt_1234567890"),
            masked_hint="vt_1...7890",
        )
        inv = DomainInvestigation(
            organization_id=org.id,
            target_input="example.com",
            normalized_domain="example.com",
            input_type=IndicatorInputType.DOMAIN,
            status="COMPLETED",
            risk_tier=DomainRiskTier.INFORMATIONAL,
            confidence_score=0.8,
        )
        self.db.add_all([cred, inv])
        self.db.commit()
        self.db.refresh(inv)

        prov = DomainProviderResult(
            investigation_id=inv.id,
            provider_name="rdap_whois",
            status=ProviderQueryStatus.SUCCESS,
            latency_ms=120,
        )
        ind = DomainIndicator(
            investigation_id=inv.id,
            indicator_type="IP",
            indicator_value="93.184.216.34",
            source="dns",
            confidence=100,
        )
        hist = DomainReputationHistory(
            organization_id=org.id,
            investigation_id=inv.id,
            normalized_domain="example.com",
            risk_tier=DomainRiskTier.INFORMATIONAL,
        )
        self.db.add_all([prov, ind, hist])
        self.db.commit()

        self.assertEqual(self.db.query(DomainInvestigation).count(), 1)
        self.assertEqual(self.db.query(DomainProviderResult).count(), 1)
        self.assertEqual(self.db.query(DomainIndicator).count(), 1)
        self.assertEqual(self.db.query(DomainReputationHistory).count(), 1)
        self.assertEqual(self.db.query(ProviderCredential).count(), 1)


if __name__ == "__main__":
    unittest.main()
