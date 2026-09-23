"""
Normalizer Registry
====================
Central factory mapping vendor strings to vendor-specific normalizer instances.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from app.normalization.cisco_normalizer import CiscoNormalizer
from app.normalization.fortinet_normalizer import FortinetNormalizer
from app.normalization.juniper_normalizer import JuniperNormalizer
from app.normalization.models import NormalizationStatusEnum, NormalizedConfiguration
from app.normalization.normalizer import BaseNormalizer
from app.parsers.base import ParsedConfiguration, ParserStatusEnum

logger = logging.getLogger("ncasa.normalization.registry")


class NormalizerRegistry:
    """Central registry mapping vendor strings to normalizer instances."""

    def __init__(self) -> None:
        self._normalizers: Dict[str, BaseNormalizer] = {
            "CISCO": CiscoNormalizer(),
            "JUNIPER": JuniperNormalizer(),
            "FORTINET": FortinetNormalizer(),
        }

    def get_normalizer(self, vendor: str) -> Optional[BaseNormalizer]:
        """Look up normalizer by vendor name (case-insensitive)."""
        if not vendor:
            return None
        return self._normalizers.get(vendor.upper())

    def normalize_parsed_configuration(
        self,
        parsed_config: ParsedConfiguration,
    ) -> NormalizedConfiguration:
        """
        Dispatch parsed configuration to the appropriate vendor normalizer.
        If vendor is UNKNOWN or unsupported, returns a NOT_SUPPORTED result.
        """
        if parsed_config.status != ParserStatusEnum.PARSED:
            logger.info("File %s status is %s; skipping normalization", parsed_config.file_id, parsed_config.status)
            return NormalizedConfiguration(
                file_id=parsed_config.file_id,
                vendor=parsed_config.vendor or "Unknown",
                device_type=parsed_config.device_type or "Unknown",
                status=NormalizationStatusEnum.NOT_SUPPORTED,
                normalizer="None",
                unsupported_reason=(
                    f"Configuration for file '{parsed_config.file_id}' was not successfully parsed. "
                    "Cannot perform normalization."
                ),
            )

        normalizer = self.get_normalizer(parsed_config.vendor)
        if normalizer is None:
            logger.info("Vendor '%s' for file '%s' has no normalizer registered", parsed_config.vendor, parsed_config.file_id)
            return NormalizedConfiguration(
                file_id=parsed_config.file_id,
                vendor=parsed_config.vendor or "Unknown",
                device_type=parsed_config.device_type or "Unknown",
                status=NormalizationStatusEnum.NOT_SUPPORTED,
                normalizer="None",
                unsupported_reason=(
                    f"Vendor '{parsed_config.vendor}' is not supported by the deterministic normalization engine."
                ),
            )

        try:
            return normalizer.normalize(parsed_config)
        except Exception as err:
            logger.error("Error normalizing file %s with normalizer %s: %s", parsed_config.file_id, normalizer.__class__.__name__, err, exc_info=True)
            return NormalizedConfiguration(
                file_id=parsed_config.file_id,
                vendor=parsed_config.vendor,
                device_type=parsed_config.device_type,
                status=NormalizationStatusEnum.FAILED,
                normalizer=normalizer.__class__.__name__,
                unsupported_reason=f"Normalization execution failed: {str(err)}",
            )


normalizer_registry = NormalizerRegistry()
