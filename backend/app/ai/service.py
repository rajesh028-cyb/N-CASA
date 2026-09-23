"""
N-CASA AI Service
==================
Main orchestrator for AI-assisted unknown-vendor configuration analysis,
secret redaction, evidence verification, normalized model synthesis, and finding explanations.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.ai.models import (
    AIParsedOutput,
    AIAnalysisFileResult,
    AIAnalysisSummary,
    AIExplanationRecord,
)
from app.ai.provider import BaseAIProvider, MockAIProvider, OpenAICompatibleProvider
from app.ai.validators import redact_secrets, validate_ai_output
from app.normalization.models import (
    NormalizedConfiguration,
    NormalizationStatusEnum,
    NormalizedIdentity,
    NormalizedManagement,
    NormalizedSSH,
    NormalizedTelnet,
    NormalizedHTTP,
    NormalizedHTTPS,
    NormalizedAuthentication,
    NormalizedInterface,
    NormalizedLogging,
    NormalizedNTP,
    NormalizedEvidenceItem,
)

logger = logging.getLogger(__name__)


class AIService:
    """Service managing AI analysis workflows."""

    def __init__(self, provider: Optional[BaseAIProvider] = None):
        if provider:
            self.provider = provider
        elif settings.AI_PROVIDER != "mock" and settings.AI_API_KEY:
            self.provider = OpenAICompatibleProvider(
                api_key=settings.AI_API_KEY,
                model=settings.AI_MODEL,
                base_url=settings.AI_BASE_URL,
                timeout_seconds=settings.AI_TIMEOUT_SECONDS,
            )
        else:
            self.provider = MockAIProvider()

    def analyze_unknown_configurations(
        self,
        audit_id: str,
        inventory_items: List[Any],
        raw_content_map: Dict[str, str],
    ) -> Tuple[AIAnalysisSummary, Dict[str, NormalizedConfiguration]]:
        """
        Processes configuration files in inventory where `vendor == UNKNOWN`.
        Redacts secrets, passes through AI Provider, validates line evidence,
        and constructs AI-assisted NormalizedConfigurations for Block 7 compliance evaluation.

        Returns (AIAnalysisSummary, dict of file_id -> NormalizedConfiguration).
        """
        if not settings.AI_ENABLED and settings.AI_PROVIDER == "disabled":
            return (
                AIAnalysisSummary(
                    audit_id=audit_id,
                    status="AI_DISABLED",
                    enabled=False,
                    total_files=len(inventory_items),
                    analyzed_files=0,
                    files=[],
                ),
                {},
            )

        summary_files: List[AIAnalysisFileResult] = []
        ai_normalized_configs: Dict[str, NormalizedConfiguration] = {}

        KNOWN_VENDORS = {"CISCO", "JUNIPER", "FORTINET"}
        unknown_items = []
        for item in inventory_items:
            v_val = getattr(item, "vendor", None) or (item.get("vendor") if isinstance(item, dict) else None)
            if not v_val or str(v_val).upper() not in KNOWN_VENDORS:
                unknown_items.append(item)

        for item in unknown_items:
            file_id = getattr(item, "file_id", item.get("file_id") if isinstance(item, dict) else "")
            filename = getattr(item, "filename", item.get("filename") if isinstance(item, dict) else file_id)

            raw_text = raw_content_map.get(file_id, "")
            if not raw_text:
                summary_files.append(
                    AIAnalysisFileResult(
                        file_id=file_id,
                        status="SKIPPED_NO_CONTENT",
                        vendor_hypothesis="Unknown",
                        confidence=0.0,
                        error="Raw configuration file content unavailable.",
                    )
                )
                continue

            # 1. Redact secrets
            redacted_text, redactions = redact_secrets(raw_text)

            # 2. Invoke AI Provider
            try:
                raw_parsed: AIParsedOutput = self.provider.analyze_config(file_id, redacted_text)

                # 3. Validate line evidence & cross-check with original config lines
                validated_parsed: AIParsedOutput = validate_ai_output(raw_text, raw_parsed)

                hyp_name = validated_parsed.vendor_hypothesis.get("name", "Unknown")
                hyp_conf = validated_parsed.vendor_hypothesis.get("confidence", 0.0)

                summary_files.append(
                    AIAnalysisFileResult(
                        file_id=file_id,
                        status="COMPLETED",
                        vendor_hypothesis=hyp_name,
                        confidence=hyp_conf,
                        parsed_output=validated_parsed,
                    )
                )

                # 4. Synthesize AI-Assisted NormalizedConfiguration
                norm_config = self._map_ai_parsed_to_normalized(file_id, filename, hyp_name, raw_text, validated_parsed)
                ai_normalized_configs[file_id] = norm_config

            except Exception as err:
                logger.error(f"Error executing AI analysis for file {file_id}: {err}")
                summary_files.append(
                    AIAnalysisFileResult(
                        file_id=file_id,
                        status="FAILED",
                        vendor_hypothesis="Unknown",
                        confidence=0.0,
                        error=str(err),
                    )
                )

        summary = AIAnalysisSummary(
            audit_id=audit_id,
            status="AI_ANALYSIS_COMPLETE",
            enabled=settings.AI_ENABLED or settings.AI_PROVIDER == "mock",
            total_files=len(inventory_items),
            analyzed_files=len(summary_files),
            files=summary_files,
        )

        return summary, ai_normalized_configs

    def _map_ai_parsed_to_normalized(
        self,
        file_id: str,
        filename: str,
        detected_vendor: str,
        raw_config_text: str,
        parsed: AIParsedOutput,
    ) -> NormalizedConfiguration:
        """
        Maps validated AI structured output to standard N-CASA NormalizedConfiguration.
        """
        evidence_items: list[NormalizedEvidenceItem] = []

        # Identity
        hostname_val = parsed.identity.hostname.value
        for e in parsed.identity.hostname.evidence:
            evidence_items.append(
                NormalizedEvidenceItem(
                    field="identity.hostname",
                    value=hostname_val,
                    source_vendor=detected_vendor,
                    source_file=file_id,
                    source_line=e.line_start,
                    source_text=e.text,
                    source="ai_assistant",
                )
            )

        # Management
        mgmt = parsed.management
        if mgmt.ssh_enabled.value is not None:
            for e in mgmt.ssh_enabled.evidence:
                evidence_items.append(
                    NormalizedEvidenceItem(
                        field="management.ssh.enabled",
                        value=mgmt.ssh_enabled.value,
                        source_vendor=detected_vendor,
                        source_file=file_id,
                        source_line=e.line_start,
                        source_text=e.text,
                        source="ai_assistant",
                    )
                )

        if mgmt.telnet_enabled.value is not None:
            for e in mgmt.telnet_enabled.evidence:
                evidence_items.append(
                    NormalizedEvidenceItem(
                        field="management.telnet.enabled",
                        value=mgmt.telnet_enabled.value,
                        source_vendor=detected_vendor,
                        source_file=file_id,
                        source_line=e.line_start,
                        source_text=e.text,
                        source="ai_assistant",
                    )
                )

        if mgmt.http_enabled.value is not None:
            for e in mgmt.http_enabled.evidence:
                evidence_items.append(
                    NormalizedEvidenceItem(
                        field="management.http.enabled",
                        value=mgmt.http_enabled.value,
                        source_vendor=detected_vendor,
                        source_file=file_id,
                        source_line=e.line_start,
                        source_text=e.text,
                        source="ai_assistant",
                    )
                )

        if mgmt.https_enabled.value is not None:
            for e in mgmt.https_enabled.evidence:
                evidence_items.append(
                    NormalizedEvidenceItem(
                        field="management.https.enabled",
                        value=mgmt.https_enabled.value,
                        source_vendor=detected_vendor,
                        source_file=file_id,
                        source_line=e.line_start,
                        source_text=e.text,
                        source="ai_assistant",
                    )
                )

        # Authentication
        auth = parsed.authentication
        if auth.enable_secret_present.value is not None:
            for e in auth.enable_secret_present.evidence:
                evidence_items.append(
                    NormalizedEvidenceItem(
                        field="authentication.enable_secret_present",
                        value=auth.enable_secret_present.value,
                        source_vendor=detected_vendor,
                        source_file=file_id,
                        source_line=e.line_start,
                        source_text=e.text,
                        source="ai_assistant",
                    )
                )

        # Interfaces
        norm_interfaces: list[NormalizedInterface] = []
        for iface in parsed.interfaces:
            norm_interfaces.append(
                NormalizedInterface(
                    name=iface.interface_name,
                    enabled=iface.enabled.value,
                    ip_addresses=[iface.ip_address.value] if iface.ip_address.value else [],
                )
            )

        # Logging & NTP
        logging_val = parsed.logging_remote_servers.value
        for e in parsed.logging_remote_servers.evidence:
            evidence_items.append(
                NormalizedEvidenceItem(
                    field="logging.remote_servers",
                    value=logging_val,
                    source_vendor=detected_vendor,
                    source_file=file_id,
                    source_line=e.line_start,
                    source_text=e.text,
                    source="ai_assistant",
                )
            )

        ntp_val = parsed.ntp_servers.value
        for e in parsed.ntp_servers.evidence:
            evidence_items.append(
                NormalizedEvidenceItem(
                    field="ntp.servers",
                    value=ntp_val,
                    source_vendor=detected_vendor,
                    source_file=file_id,
                    source_line=e.line_start,
                    source_text=e.text,
                    source="ai_assistant",
                )
            )

        return NormalizedConfiguration(
            file_id=file_id,
            vendor=detected_vendor.upper() if detected_vendor != "Unknown" else "UNKNOWN",
            device_type=parsed.device_type.get("value", "Unknown"),
            status=NormalizationStatusEnum.NORMALIZED,
            normalizer="AINormalizer",
            normalization_method="AI_ASSISTED",
            identity=NormalizedIdentity(
                hostname=hostname_val,
            ),
            management=NormalizedManagement(
                ssh=NormalizedSSH(
                    enabled=mgmt.ssh_enabled.value,
                    version=mgmt.ssh_version.value,
                ),
                telnet=NormalizedTelnet(
                    enabled=mgmt.telnet_enabled.value,
                ),
                http=NormalizedHTTP(
                    enabled=mgmt.http_enabled.value,
                ),
                https=NormalizedHTTPS(
                    enabled=mgmt.https_enabled.value,
                ),
            ),
            authentication=NormalizedAuthentication(
                enable_secret_present=auth.enable_secret_present.value,
                aaa_enabled=auth.aaa_enabled.value,
            ),
            interfaces=norm_interfaces,
            logging=NormalizedLogging(
                enabled=True if logging_val else (False if logging_val == [] else None),
                remote_servers=logging_val if isinstance(logging_val, list) else [],
            ),
            ntp=NormalizedNTP(
                enabled=True if ntp_val else (False if ntp_val == [] else None),
                servers=ntp_val if isinstance(ntp_val, list) else [],
            ),
            evidence=evidence_items,
        )

    def explain_finding(
        self,
        finding: Dict[str, Any],
        evidence_lines: List[Dict[str, Any]],
        config_snippet: str,
        vendor: str = "UNKNOWN",
        device_type: str = "Unknown",
    ) -> AIExplanationRecord:
        """
        Generates a structured AI explanation for a given compliance finding.
        """
        return self.provider.explain_finding(
            finding=finding,
            evidence_lines=evidence_lines,
            config_snippet=config_snippet,
            vendor=vendor,
            device_type=device_type,
        )


# Global default service instance
ai_service = AIService()
