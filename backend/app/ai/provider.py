"""
N-CASA AI Providers
===================
1. BaseAIProvider: Interface definition.
2. MockAIProvider: Deterministic, heuristic fallback for offline unknown-vendor parsing and testing.
3. OpenAICompatibleProvider: Integration with OpenAI / vLLM / Ollama REST APIs.
"""

from abc import ABC, abstractmethod
import json
import logging
import re
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import settings
from app.ai.models import (
    AIEvidence,
    AIParsedField,
    AIIdentityFields,
    AIManagementFields,
    AIAuthenticationFields,
    AIInterfaceField,
    AIParsedOutput,
    AIExplanationRecord,
)
from app.ai.prompts import (
    UNKNOWN_VENDOR_SYSTEM_PROMPT,
    UNKNOWN_VENDOR_USER_PROMPT_TEMPLATE,
    FINDING_EXPLANATION_SYSTEM_PROMPT,
    FINDING_EXPLANATION_USER_PROMPT_TEMPLATE,
)

logger = logging.getLogger(__name__)


class BaseAIProvider(ABC):
    """Abstract interface for AI analysis providers."""

    @abstractmethod
    def analyze_config(self, file_id: str, raw_config_text: str) -> AIParsedOutput:
        """Analyzes redacted raw configuration text of an unknown vendor."""
        pass

    @abstractmethod
    def explain_finding(
        self,
        finding: Dict[str, Any],
        evidence_lines: List[Dict[str, Any]],
        config_snippet: str,
        vendor: str,
        device_type: str,
    ) -> AIExplanationRecord:
        """Generates a structured explanation for a security finding."""
        pass


class MockAIProvider(BaseAIProvider):
    """
    Deterministic Mock AI Provider for offline testing and evaluation.
    Scans raw configuration text for vendor indicators (Mikrotik, HP ProCurve, VyOS, Palo Alto)
    and extracts structured parameters with valid 1-indexed line evidence.
    """

    def analyze_config(self, file_id: str, raw_config_text: str) -> AIParsedOutput:
        lines = raw_config_text.splitlines()

        vendor_name = "Unknown"
        device_type_val = "Unknown"
        vendor_confidence = 0.0
        vendor_evidence: List[AIEvidence] = []

        hostname_val: Optional[str] = None
        hostname_ev: List[AIEvidence] = []

        ssh_enabled_val: Optional[bool] = None
        ssh_ev: List[AIEvidence] = []

        telnet_enabled_val: Optional[bool] = None
        telnet_ev: List[AIEvidence] = []

        http_enabled_val: Optional[bool] = None
        http_ev: List[AIEvidence] = []

        https_enabled_val: Optional[bool] = None
        https_ev: List[AIEvidence] = []

        enable_secret_val: Optional[bool] = None
        enable_secret_ev: List[AIEvidence] = []

        interfaces: List[AIInterfaceField] = []
        logging_servers: List[str] = []
        logging_ev: List[AIEvidence] = []

        ntp_servers: List[str] = []
        ntp_ev: List[AIEvidence] = []

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()

            # Mikrotik RouterOS
            if "/ip service" in line_str or "/system identity" in line_str or "routeros" in line_str.lower():
                vendor_name = "Mikrotik"
                device_type_val = "Router"
                vendor_confidence = 0.92
                vendor_evidence.append(
                    AIEvidence(
                        line_start=idx,
                        line_end=idx,
                        text=line_str,
                        field="vendor",
                        explanation="Mikrotik RouterOS configuration syntax detected",
                    )
                )

            # VyOS / Vyatta
            elif "system {" in line_str or "interfaces {" in line_str or "vyos" in line_str.lower():
                vendor_name = "VyOS"
                device_type_val = "Router"
                vendor_confidence = 0.88
                vendor_evidence.append(
                    AIEvidence(
                        line_start=idx,
                        line_end=idx,
                        text=line_str,
                        field="vendor",
                        explanation="VyOS configuration block syntax detected",
                    )
                )

            # HP / Aruba ProCurve
            elif "hostname" in line_str.lower() and "hp" in line_str.lower() or "module" in line_str.lower():
                if vendor_name == "Unknown":
                    vendor_name = "HP Enterprise"
                    device_type_val = "Switch"
                    vendor_confidence = 0.85
                    vendor_evidence.append(
                        AIEvidence(
                            line_start=idx,
                            line_end=idx,
                            text=line_str,
                            field="vendor",
                            explanation="HP ProCurve switch configuration line detected",
                        )
                    )

            # Hostname detection
            if "name=" in line_str.lower() or "host-name" in line_str.lower() or line_str.lower().startswith("hostname "):
                parts = line_str.split()
                if len(parts) >= 2:
                    raw_val = parts[-1]
                    for marker in ["name=", "host-name="]:
                        if marker in raw_val.lower():
                            raw_val = raw_val.split("=", 1)[-1]
                    hostname_val = raw_val.strip("'\"")
                    hostname_ev.append(
                        AIEvidence(
                            line_start=idx,
                            line_end=idx,
                            text=line_str,
                            field="hostname",
                            explanation="Device hostname statement",
                        )
                    )

            # SSH detection
            if "set ssh" in line_str.lower() or "ip ssh" in line_str.lower() or "set ip service ssh disabled=no" in line_str.lower():
                ssh_enabled_val = True
                ssh_ev.append(
                    AIEvidence(
                        line_start=idx,
                        line_end=idx,
                        text=line_str,
                        field="ssh_enabled",
                        explanation="SSH management service enabled",
                    )
                )
            elif "disabled=yes" in line_str.lower() and "ssh" in line_str.lower():
                ssh_enabled_val = False
                ssh_ev.append(
                    AIEvidence(
                        line_start=idx,
                        line_end=idx,
                        text=line_str,
                        field="ssh_enabled",
                        explanation="SSH management service explicitly disabled",
                    )
                )

            # Telnet detection
            if "disabled=yes" in line_str.lower() and "telnet" in line_str.lower():
                telnet_enabled_val = False
                telnet_ev.append(
                    AIEvidence(
                        line_start=idx,
                        line_end=idx,
                        text=line_str,
                        field="telnet_enabled",
                        explanation="Telnet management service disabled",
                    )
                )
            elif "set telnet" in line_str.lower() or "ip telnet" in line_str.lower() or "disabled=no" in line_str.lower() and "telnet" in line_str.lower():
                telnet_enabled_val = True
                telnet_ev.append(
                    AIEvidence(
                        line_start=idx,
                        line_end=idx,
                        text=line_str,
                        field="telnet_enabled",
                        explanation="Insecure Telnet management service enabled",
                    )
                )

            # HTTP / HTTPS detection
            if "web-management" in line_str.lower() or "ip http server" in line_str.lower() or "service set www" in line_str.lower() or "set www disabled=no" in line_str.lower():
                http_enabled_val = True
                http_ev.append(
                    AIEvidence(
                        line_start=idx,
                        line_end=idx,
                        text=line_str,
                        field="http_enabled",
                        explanation="Insecure HTTP web management enabled",
                    )
                )
            if "ip http secure-server" in line_str.lower() or "set ip service www-ssl disabled=no" in line_str.lower():
                https_enabled_val = True
                https_ev.append(
                    AIEvidence(
                        line_start=idx,
                        line_end=idx,
                        text=line_str,
                        field="https_enabled",
                        explanation="Secure HTTPS web management enabled",
                    )
                )

            # Enable secret / password
            if "enable secret" in line_str.lower() or "password" in line_str.lower():
                enable_secret_val = True
                enable_secret_ev.append(
                    AIEvidence(
                        line_start=idx,
                        line_end=idx,
                        text=line_str,
                        field="enable_secret_present",
                        explanation="Authentication secret/password directive found",
                    )
                )

            # Logging servers
            if "syslog" in line_str.lower() or "logging" in line_str.lower():
                parts = line_str.split()
                for p in parts:
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', p):
                        logging_servers.append(p)
                        logging_ev.append(
                            AIEvidence(
                                line_start=idx,
                                line_end=idx,
                                text=line_str,
                                field="logging_remote_servers",
                                explanation="Remote syslog server configured",
                            )
                        )

            # NTP servers
            if "ntp" in line_str.lower() and ("server" in line_str.lower() or "set" in line_str.lower()):
                parts = line_str.split()
                for p in parts:
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', p):
                        ntp_servers.append(p)
                        ntp_ev.append(
                            AIEvidence(
                                line_start=idx,
                                line_end=idx,
                                text=line_str,
                                field="ntp_servers",
                                explanation="NTP time server configured",
                            )
                        )

        # Fallback vendor hypothesis if unidentified
        if vendor_name == "Unknown":
            vendor_confidence = 0.0
            device_type_val = "Unknown"

        return AIParsedOutput(
            vendor_hypothesis={"name": vendor_name, "confidence": vendor_confidence, "evidence": [e.model_dump() for e in vendor_evidence]},
            device_type={"value": device_type_val, "confidence": vendor_confidence, "evidence": [e.model_dump() for e in vendor_evidence]},
            identity=AIIdentityFields(
                hostname=AIParsedField(value=hostname_val, confidence=0.85 if hostname_val else 0.0, evidence=hostname_ev)
            ),
            management=AIManagementFields(
                ssh_enabled=AIParsedField(value=ssh_enabled_val, confidence=0.85 if ssh_enabled_val is not None else 0.0, evidence=ssh_ev),
                ssh_version=AIParsedField(value=None, confidence=0.0, evidence=[]),
                telnet_enabled=AIParsedField(value=telnet_enabled_val, confidence=0.85 if telnet_enabled_val is not None else 0.0, evidence=telnet_ev),
                http_enabled=AIParsedField(value=http_enabled_val, confidence=0.85 if http_enabled_val is not None else 0.0, evidence=http_ev),
                https_enabled=AIParsedField(value=https_enabled_val, confidence=0.85 if https_enabled_val is not None else 0.0, evidence=https_ev),
            ),
            authentication=AIAuthenticationFields(
                enable_secret_present=AIParsedField(value=enable_secret_val, confidence=0.85 if enable_secret_val is not None else 0.0, evidence=enable_secret_ev),
                aaa_enabled=AIParsedField(value=None, confidence=0.0, evidence=[]),
            ),
            interfaces=interfaces,
            logging_remote_servers=AIParsedField(
                value=list(set(logging_servers)) if logging_servers else None,
                confidence=0.85 if logging_servers else 0.0,
                evidence=logging_ev,
            ),
            ntp_servers=AIParsedField(
                value=list(set(ntp_servers)) if ntp_servers else None,
                confidence=0.85 if ntp_servers else 0.0,
                evidence=ntp_ev,
            ),
        )

    def explain_finding(
        self,
        finding: Dict[str, Any],
        evidence_lines: List[Dict[str, Any]],
        config_snippet: str,
        vendor: str,
        device_type: str,
    ) -> AIExplanationRecord:
        finding_id = finding.get("id", "FND-000")
        title = finding.get("title", "Configuration Finding")
        status = finding.get("status", "FAIL")
        severity = finding.get("severity", "MEDIUM")

        evidence_items = []
        for ev in evidence_lines:
            evidence_items.append(
                AIEvidence(
                    line_start=ev.get("line_number", 1),
                    line_end=ev.get("line_number", 1),
                    text=ev.get("line_content", ""),
                    field=finding.get("control_id", "security_control"),
                    explanation=f"Configuration line referenced for {title}",
                )
            )

        summary = f"Finding {finding_id} ({title}) assessed as {status} on {vendor} ({device_type})."
        security_impact = (
            f"Non-compliance with security control {finding.get('control_id')} exposes the system to increased risk "
            f"associated with {finding.get('category', 'security parameters')}. Severity rating: {severity}."
        )
        evidence_interpretation = (
            f"The configuration evidence shows matching lines where required security parameters are either missing or "
            f"configured insecurely. Evaluated line content: '{evidence_lines[0]['line_content'] if evidence_lines else 'N/A'}'."
        )
        recommended_review = (
            "Review device administration policy, verify operational necessity, and validate configuration changes "
            "in a staging environment prior to applying remediation commands."
        )

        return AIExplanationRecord(
            finding_id=finding_id,
            summary=summary,
            security_impact=security_impact,
            evidence_interpretation=evidence_interpretation,
            recommended_review=recommended_review,
            confidence=0.90,
            evidence=evidence_items,
        )


class OpenAICompatibleProvider(BaseAIProvider):
    """
    OpenAI-compatible REST API client (supports OpenAI, Azure OpenAI, vLLM, LocalAI, Ollama).
    """

    def __init__(self, api_key: str, model: str, base_url: str = "", timeout_seconds: int = 60):
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.timeout = timeout_seconds

    def analyze_config(self, file_id: str, raw_config_text: str) -> AIParsedOutput:
        prompt = UNKNOWN_VENDOR_USER_PROMPT_TEMPLATE.format(
            file_id=file_id,
            config_text=raw_config_text,
        )

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": UNKNOWN_VENDOR_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                parsed_json = json.loads(content)
                parsed_obj = AIParsedOutput.model_validate(parsed_json)
                parsed_obj.raw_json = parsed_json
                return parsed_obj
        except Exception as err:
            logger.error(f"AI Provider error during analyze_config: {err}")
            # Fallback to empty un-analyzed output on external API failure
            return AIParsedOutput()

    def explain_finding(
        self,
        finding: Dict[str, Any],
        evidence_lines: List[Dict[str, Any]],
        config_snippet: str,
        vendor: str,
        device_type: str,
    ) -> AIExplanationRecord:
        finding_id = finding.get("id", "FND-000")
        ev_text = "\n".join([f"Line {e.get('line_number')}: {e.get('line_content')}" for e in evidence_lines])

        prompt = FINDING_EXPLANATION_USER_PROMPT_TEMPLATE.format(
            finding_id=finding_id,
            title=finding.get("title", ""),
            control_id=finding.get("control_id", ""),
            severity=finding.get("severity", ""),
            category=finding.get("category", ""),
            status=finding.get("status", ""),
            description=finding.get("description", ""),
            rationale=finding.get("rationale", ""),
            evidence_lines_text=ev_text or "No specific evidence lines provided.",
            vendor=vendor,
            device_type=device_type,
            config_snippet=config_snippet[:1000],
        )

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": FINDING_EXPLANATION_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                parsed_json = json.loads(content)
                return AIExplanationRecord.model_validate(parsed_json)
        except Exception as err:
            logger.error(f"AI Provider error during explain_finding: {err}")
            # Fallback mock explanation on external failure
            mock_prov = MockAIProvider()
            return mock_prov.explain_finding(finding, evidence_lines, config_snippet, vendor, device_type)
