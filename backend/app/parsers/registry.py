"""
Parser Registry
================
Central factory and dispatcher mapping vendor names to vendor-specific parsers.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from app.parsers.base import BaseParser, ParsedConfiguration, ParserStatusEnum
from app.parsers.cisco_parser import CiscoParser
from app.parsers.fortinet_parser import FortinetParser
from app.parsers.juniper_parser import JuniperParser

logger = logging.getLogger("ncasa.parsers.registry")


class ParserRegistry:
    """Central registry mapping vendor strings to parser instances."""

    def __init__(self) -> None:
        self._parsers: Dict[str, BaseParser] = {
            "CISCO": CiscoParser(),
            "JUNIPER": JuniperParser(),
            "FORTINET": FortinetParser(),
        }

    def get_parser(self, vendor: str) -> Optional[BaseParser]:
        """Look up parser by vendor name (case-insensitive)."""
        if not vendor:
            return None
        return self._parsers.get(vendor.upper())

    def parse_configuration(
        self,
        file_id: str,
        vendor: str,
        device_type: str,
        content: str,
    ) -> ParsedConfiguration:
        """
        Dispatch configuration content to the appropriate vendor parser.
        If vendor is UNKNOWN or unsupported, returns a clean NOT_PARSED result.
        """
        parser = self.get_parser(vendor)
        if parser is None:
            logger.info("Vendor '%s' for file '%s' has no deterministic parser available", vendor, file_id)
            return ParsedConfiguration(
                file_id=file_id,
                vendor=vendor or "Unknown",
                device_type=device_type or "Unknown",
                status=ParserStatusEnum.NOT_PARSED,
                parser="None",
                data={},
                evidence=[],
                unsupported_reason=(
                    f"Configuration vendor '{vendor}' is outside the supported deterministic parser set. "
                    "AI-assisted configuration understanding will be introduced in Block 10."
                ),
            )

        try:
            return parser.parse(
                file_id=file_id,
                content=content,
                device_type=device_type,
                vendor=vendor,
            )
        except Exception as err:
            logger.error("Error parsing file %s with parser %s: %s", file_id, parser.__class__.__name__, err, exc_info=True)
            return ParsedConfiguration(
                file_id=file_id,
                vendor=vendor,
                device_type=device_type,
                status=ParserStatusEnum.FAILED,
                parser=parser.__class__.__name__,
                data={},
                evidence=[],
                unsupported_reason=f"Parser execution failed: {str(err)}",
            )


parser_registry = ParserRegistry()
