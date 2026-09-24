"""
N-CASA Sensitive Data Redaction Utilities
=========================================
Sanitizes sensitive values (passwords, secrets, PSKs, private keys) from configuration snippets.
"""

from __future__ import annotations

import re
from typing import Any

# Secret Sanitization Patterns
SECRET_PATTERNS = [
    (re.compile(r'(?i)\b(password|secret|enable\s+secret|pre-shared-key|psk|md5-key|community)\s+.*$', re.MULTILINE), r'\1 <REDACTED>'),
    (re.compile(r'-----BEGIN\s+.*?\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+.*?\s+PRIVATE\s+KEY-----', re.IGNORECASE), r'<REDACTED PRIVATE KEY>'),
]


def redact_secrets_text(text: str) -> str:
    """Sanitize secret values from configuration and evidence text snippets."""
    if not text or not isinstance(text, str):
        return text
    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def redact_secrets_obj(obj: Any) -> Any:
    """Recursively scrub secrets from dicts, lists, and strings."""
    if isinstance(obj, str):
        return redact_secrets_text(obj)
    elif isinstance(obj, dict):
        new_dict = {}
        for k, v in obj.items():
            if k.lower() in ("password", "secret", "psk", "private_key", "api_key", "token", "community"):
                new_dict[k] = "<REDACTED>"
            else:
                new_dict[k] = redact_secrets_obj(v)
        return new_dict
    elif isinstance(obj, list):
        return [redact_secrets_obj(item) for item in obj]
    return obj
