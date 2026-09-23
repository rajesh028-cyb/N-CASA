"""
N-CASA AI Validators & Secret Redaction
========================================
1. Secret Redaction: Protect sensitive credentials prior to external LLM transmission.
2. Line-Level Evidence Cross-Checking: Enforce line index validity and exact string matching.
3. Confidence Thresholding & Validation Flagging: Reject invalid evidence or un-evidenced values.
"""

import re
from typing import List, Tuple
from app.ai.models import AIParsedField, AIParsedOutput, AIEvidence


SECRET_PATTERNS = [
    re.compile(r'(password\s+(?:encryption-type\s+\d+\s+)?)([\'\"]?[^\s\'\"]+[\'\"]?)', re.IGNORECASE),
    re.compile(r'(secret\s+(?:5|8|9|0)?\s*)([\'\"]?[^\s\'\"]+[\'\"]?)', re.IGNORECASE),
    re.compile(r'(community\s+)([\'\"]?[^\s\'\"]+[\'\"]?)', re.IGNORECASE),
    re.compile(r'((?:pre-shared-key|preshared-key|key-string|psk)\s+)([\'\"]?[^\s\'\"]+[\'\"]?)', re.IGNORECASE),
    re.compile(r'(auth-password|priv-password)\s+([^\s]+)', re.IGNORECASE),
]


def redact_secrets(raw_text: str) -> Tuple[str, int]:
    """
    Redacts sensitive credentials from configuration text prior to sending to AI.
    Replaces matched password/secret values with `<REDACTED>`.
    Returns (redacted_text, redaction_count).
    """
    redaction_count = 0
    redacted_text = raw_text

    for pattern in SECRET_PATTERNS:
        def replace_match(m):
            nonlocal redaction_count
            prefix = m.group(1)
            val = m.group(2)
            if val == "<REDACTED>":
                return m.group(0)
            redaction_count += 1
            return f"{prefix}<REDACTED>"

        redacted_text = pattern.sub(replace_match, redacted_text)

    return redacted_text, redaction_count


def validate_evidence(raw_lines: List[str], evidence_list: List[AIEvidence]) -> List[AIEvidence]:
    """
    Validates evidence line numbers and line text cross-checks against raw configuration lines.
    Rules:
    - 1-indexed lines: 1 <= line_start <= line_end <= len(raw_lines)
    - Line text cross-check: fuzzy or exact check that raw lines contain portion of evidence text
    """
    valid_evidence: List[AIEvidence] = []
    num_lines = len(raw_lines)

    for item in evidence_list:
        if item.line_start < 1 or item.line_end > num_lines or item.line_start > item.line_end:
            continue  # Out of bounds line numbers

        # Slice actual lines (converting 1-based to 0-based index)
        actual_lines_text = "\n".join(raw_lines[item.line_start - 1 : item.line_end]).strip()
        ev_text_clean = item.text.strip()

        # Simple verification: text in evidence should be in actual lines or vice-versa (ignoring redacted tokens)
        ev_compare = ev_text_clean.replace("<REDACTED>", "")
        act_compare = actual_lines_text.replace("<REDACTED>", "")

        if ev_compare in act_compare or act_compare in ev_compare or len(ev_compare) == 0:
            valid_evidence.append(item)
        else:
            # If text line check failed completely, skip
            pass

    return valid_evidence


def validate_parsed_field(raw_lines: List[str], field: AIParsedField) -> AIParsedField:
    """
    Validates an individual AIParsedField:
    - Validates line evidence.
    - If value is not None but valid evidence is empty -> set value = None, confidence = 0.0 ("No evidence = no value").
    - If confidence < 0.65 -> set requires_manual_validation = True.
    """
    if field.value is None:
        field.evidence = []
        field.confidence = 0.0
        field.requires_manual_validation = False
        return field

    field.evidence = validate_evidence(raw_lines, field.evidence)

    if not field.evidence:
        # Enforce Hard Rule: No valid line evidence = no value
        field.value = None
        field.confidence = 0.0
        field.requires_manual_validation = False
    else:
        if field.confidence < 0.65:
            field.requires_manual_validation = True
        else:
            field.requires_manual_validation = False

    return field


def validate_ai_output(raw_config_text: str, parsed: AIParsedOutput) -> AIParsedOutput:
    """
    Cross-checks an entire AIParsedOutput object against raw config lines.
    Validates all field evidence, confidence thresholds, and invalidates ungrounded data.
    """
    raw_lines = raw_config_text.splitlines()

    # Validate vendor hypothesis evidence
    if isinstance(parsed.vendor_hypothesis, dict):
        ev_list = [AIEvidence(**e) if isinstance(e, dict) else e for e in parsed.vendor_hypothesis.get("evidence", [])]
        valid_ev = validate_evidence(raw_lines, ev_list)
        parsed.vendor_hypothesis["evidence"] = [e.model_dump() for e in valid_ev]
        if not valid_ev and parsed.vendor_hypothesis.get("name") != "Unknown":
            parsed.vendor_hypothesis["name"] = "Unknown"
            parsed.vendor_hypothesis["confidence"] = 0.0

    # Validate device type evidence
    if isinstance(parsed.device_type, dict):
        ev_list = [AIEvidence(**e) if isinstance(e, dict) else e for e in parsed.device_type.get("evidence", [])]
        valid_ev = validate_evidence(raw_lines, ev_list)
        parsed.device_type["evidence"] = [e.model_dump() for e in valid_ev]
        if not valid_ev and parsed.device_type.get("value") != "Unknown":
            parsed.device_type["value"] = "Unknown"
            parsed.device_type["confidence"] = 0.0

    # Validate Identity
    parsed.identity.hostname = validate_parsed_field(raw_lines, parsed.identity.hostname)

    # Validate Management
    parsed.management.ssh_enabled = validate_parsed_field(raw_lines, parsed.management.ssh_enabled)
    parsed.management.ssh_version = validate_parsed_field(raw_lines, parsed.management.ssh_version)
    parsed.management.telnet_enabled = validate_parsed_field(raw_lines, parsed.management.telnet_enabled)
    parsed.management.http_enabled = validate_parsed_field(raw_lines, parsed.management.http_enabled)
    parsed.management.https_enabled = validate_parsed_field(raw_lines, parsed.management.https_enabled)

    # Validate Authentication
    parsed.authentication.enable_secret_present = validate_parsed_field(raw_lines, parsed.authentication.enable_secret_present)
    parsed.authentication.aaa_enabled = validate_parsed_field(raw_lines, parsed.authentication.aaa_enabled)

    # Validate Interfaces
    validated_interfaces = []
    for interface in parsed.interfaces:
        interface.ip_address = validate_parsed_field(raw_lines, interface.ip_address)
        interface.enabled = validate_parsed_field(raw_lines, interface.enabled)
        interface.evidence = validate_evidence(raw_lines, interface.evidence)
        validated_interfaces.append(interface)
    parsed.interfaces = validated_interfaces

    # Validate Logging & NTP
    parsed.logging_remote_servers = validate_parsed_field(raw_lines, parsed.logging_remote_servers)
    parsed.ntp_servers = validate_parsed_field(raw_lines, parsed.ntp_servers)

    return parsed
