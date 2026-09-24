"""
N-CASA Hashing Utilities
========================
Deterministic hashing and fingerprinting helpers for configuration files and audit artifacts.
"""

import hashlib


def sha256_text(text: str) -> str:
    """Compute SHA-256 hash of a string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()
