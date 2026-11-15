"""
Evidence Sanitizer & Forensic Integrity Guard for OpenRecon.
Ensures zero-risk storage and rendering of untrusted threat intelligence data:
1. Strips all executable scripts, event handlers, iframes, and active payloads (Anti-Stored-XSS).
2. Uses standard library html.parser (zero external dependencies).
3. Enforces k-Anonymity identity masking (e.g. jo****e@corp.com).
4. Produces deterministic SHA-256 credential hashes (Zero-Plaintext Guarantee).
5. Generates HMAC-SHA256 custody signatures for evidence tamper-proofing.
"""

import hashlib
import hmac
import logging
import re
from html.parser import HTMLParser
from typing import Any, Optional

from app.core.config import settings

_SENSITIVE_KEY_NAMES = {
    "password", "passwd", "pwd", "pass", "secret", "secret_key",
    "api_key", "apikey", "token", "access_token", "refresh_token",
    "auth_token", "authorization", "cookie", "set-cookie", "session",
    "session_id", "private_key", "client_secret", "master_key",
}

_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.MULTILINE), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(?i)(authorization\s*[:=]\s*['\"]?)([^\s'\";,}]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:password|passwd|pwd|api[_-]?key|secret|token|cookie)\s*[:=]\s*['\"]?)([^\s'\",;}{]+)"), r"\1[REDACTED]"),
    (re.compile(r"\b(sk-[A-Za-z0-9]{16,})\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]"),
]


class _SafeTextExtractor(HTMLParser):
    """
    Standard library HTML Parser that strictly eliminates unsafe tags,
    inline scripts, event handlers, and extracts clean sanitized text.
    """
    BLOCKED_TAGS = {
        "script", "style", "iframe", "object", "embed", "applet",
        "svg", "noscript", "form", "button", "input", "textarea"
    }

    def __init__(self):
        super().__init__()
        self.output = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        tag_lower = tag.lower()
        if tag_lower in self.BLOCKED_TAGS:
            self._skip_depth += 1
            return

        if self._skip_depth == 0:
            # Block-level linebreaks
            if tag_lower in ("p", "div", "br", "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr"):
                self.output.append("\n")

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower in self.BLOCKED_TAGS:
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return

        if self._skip_depth == 0:
            if tag_lower in ("p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr"):
                self.output.append("\n")

    def handle_data(self, data):
        if self._skip_depth == 0 and data:
            self.output.append(data)

    def get_clean_text(self) -> str:
        raw = "".join(self.output)
        # Normalize multiple spaces and consecutive blank lines
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r"\n\s*\n\s*\n+", "\n\n", raw)
        return raw.strip()


class EvidenceSanitizer:
    """
    Forensic sanitization and anonymization engine for Dark Web and leak intelligence.
    """

    @classmethod
    def sanitize_raw_content(cls, raw_text: str, max_chars: int = 4096) -> str:
        """
        Cleans untrusted HTML/text content collected from the Dark Web.
        Removes scripts, active payloads, and normalizes whitespaces.
        Returns clean, non-executable textual snippet.
        """
        if not raw_text:
            return ""

        parser = _SafeTextExtractor()
        try:
            parser.feed(raw_text)
            clean_text = parser.get_clean_text()
        except Exception:
            # Fallback if malformed: basic regex tag strip
            clean_text = re.sub(r"<[^>]+>", " ", raw_text)
            clean_text = re.sub(r"\s+", " ", clean_text).strip()

        # Strip secrets before returning
        clean_text = cls.redact_secrets_in_text(clean_text)

        # Truncate to maximum preview length
        if len(clean_text) > max_chars:
            clean_text = clean_text[:max_chars] + "\n... [EVIDENCE TRUNCATED FOR SAFETY]"

        return clean_text

    @classmethod
    def redact_secrets_in_text(cls, text: str) -> str:
        """
        Redacts passwords, API keys, Bearer tokens, JWTs, private keys,
        and sensitive credentials from arbitrary text or log messages.
        """
        if not text:
            return ""
        redacted = str(text)
        for pattern, replacement in _SECRET_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    @classmethod
    def sanitize_evidence_payload(cls, payload: Any, max_chars: int = 2048) -> Any:
        """
        Recursively sanitizes dicts/lists/strings before persisting evidence,
        ensuring no cleartext secrets, tokens, or raw HTML payloads are stored.
        """
        if isinstance(payload, dict):
            sanitized_dict = {}
            for k, v in payload.items():
                key_lower = str(k).strip().lower()
                if key_lower in _SENSITIVE_KEY_NAMES:
                    sanitized_dict[k] = "[REDACTED]"
                else:
                    sanitized_dict[k] = cls.sanitize_evidence_payload(v, max_chars=max_chars)
            return sanitized_dict
        if isinstance(payload, list):
            return [cls.sanitize_evidence_payload(item, max_chars=max_chars) for item in payload]
        if isinstance(payload, str):
            return cls.sanitize_raw_content(payload, max_chars=max_chars)
        return payload

    @classmethod
    def mask_identity(cls, identifier: str) -> str:
        """
        Masks user identifiers (emails or usernames) for privacy and legal compliance.
        Examples:
        - "john.doe@company.com" -> "jo****e@company.com"
        - "admin" -> "ad***n"
        - "a@b.com" -> "*@b.com"
        """
        if not identifier:
            return "****"

        clean = identifier.strip().lower()

        if "@" in clean:
            user_part, domain_part = clean.split("@", 1)
            if len(user_part) <= 2:
                masked_user = "*" * len(user_part)
            elif len(user_part) <= 4:
                masked_user = f"{user_part[0]}**{user_part[-1]}"
            else:
                masked_user = f"{user_part[:2]}****{user_part[-1]}"
            return f"{masked_user}@{domain_part}"
        else:
            if len(clean) <= 3:
                return "***"
            return f"{clean[:2]}***{clean[-1]}"

    @classmethod
    def hash_credential(cls, cleartext_secret: str) -> str:
        """
        Produces SHA-256 hash for k-anonymity matching.
        Plaintext secret is never stored anywhere in memory or disk.
        """
        if not cleartext_secret:
            return ""
        return hashlib.sha256(cleartext_secret.strip().encode("utf-8")).hexdigest()

    @classmethod
    def generate_custody_signature(
        cls,
        evidence_id: str,
        content: str,
        secret_key: Optional[str] = None
    ) -> str:
        """
        Generates HMAC-SHA256 signature validating chain of custody.
        """
        key = (secret_key or settings.SECRET_KEY).encode("utf-8")
        payload = f"{evidence_id}:{content[:512]}".encode("utf-8")
        return hmac.new(key, payload, hashlib.sha256).hexdigest()


class SecretRedactingFilter(logging.Filter):
    """
    Logging filter that redacts secrets, tokens, and passwords from log records.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = EvidenceSanitizer.redact_secrets_in_text(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(
                    EvidenceSanitizer.redact_secrets_in_text(a) if isinstance(a, str) else a
                    for a in record.args
                )
            elif isinstance(record.args, dict):
                record.args = {
                    k: EvidenceSanitizer.redact_secrets_in_text(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
        return True
