"""
N-CASA Vendor & Device Detection Engine
========================================
Deterministic vendor and device type classification based on signature rules,
weighted scoring, and line-level evidence collection.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Tuple

from app.detection.signatures import (
    CISCO_SIGNATURES,
    FORTINET_SIGNATURES,
    JUNIPER_SIGNATURES,
    detect_cisco_device_type,
    detect_fortinet_device_type,
    detect_juniper_device_type,
)
from app.models.detection import (
    DetectionMethodEnum,
    DetectionStatusEnum,
    DeviceTypeEnum,
    EvidenceCategory,
    EvidenceItem,
    VendorDetectionResult,
    VendorEnum,
)

logger = logging.getLogger("ncasa.detection.detector")

SCORE_MAP = {
    EvidenceCategory.STRONG: 50,
    EvidenceCategory.MEDIUM: 20,
    EvidenceCategory.WEAK: 5,
}

MIN_VENDOR_SCORE_THRESHOLD = 40  # Minimum score required to declare a known vendor


class VendorDetector:
    """Deterministic vendor & device type detection engine."""

    def detect_file(self, file_id: str, relative_path: str, content: str) -> VendorDetectionResult:
        """
        Analyze configuration text, run vendor signatures, collect line-level evidence,
        calculate confidence score, and determine vendor & device type.
        """
        lines = content.split("\n")

        scores: Dict[VendorEnum, int] = {
            VendorEnum.CISCO: 0,
            VendorEnum.JUNIPER: 0,
            VendorEnum.FORTINET: 0,
        }

        evidence_by_vendor: Dict[VendorEnum, List[EvidenceItem]] = {
            VendorEnum.CISCO: [],
            VendorEnum.JUNIPER: [],
            VendorEnum.FORTINET: [],
        }

        vendor_rules = [
            (VendorEnum.CISCO, CISCO_SIGNATURES),
            (VendorEnum.JUNIPER, JUNIPER_SIGNATURES),
            (VendorEnum.FORTINET, FORTINET_SIGNATURES),
        ]

        # 1. Scan line by line against vendor signature sets
        for line_idx, line in enumerate(lines, start=1):
            sline = line.strip()
            if not sline or sline.startswith("!") or sline.startswith("#"):
                # Still check lines for version or header comments if relevant, but skip empty
                pass

            for vendor, signatures in vendor_rules:
                for rx, label, category in signatures:
                    if rx.search(line):
                        pts = SCORE_MAP[category]
                        scores[vendor] += pts
                        evidence_by_vendor[vendor].append(
                            EvidenceItem(
                                indicator=label,
                                line=line_idx,
                                category=category,
                                vendor=vendor,
                            )
                        )

        # 2. Rank vendors by accumulated score
        ranked_vendors = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        top_vendor, top_score = ranked_vendors[0]
        second_vendor, second_score = ranked_vendors[1]

        logger.info(
            "Detection evaluation for %s (%s): Cisco=%d, Juniper=%d, Fortinet=%d | Top: %s (%d)",
            file_id, relative_path, scores[VendorEnum.CISCO], scores[VendorEnum.JUNIPER], scores[VendorEnum.FORTINET], top_vendor.value, top_score
        )

        # 3. Insufficient evidence -> UNKNOWN
        if top_score < MIN_VENDOR_SCORE_THRESHOLD:
            return VendorDetectionResult(
                file_id=file_id,
                relative_path=relative_path,
                vendor=VendorEnum.UNKNOWN,
                device_type=DeviceTypeEnum.UNKNOWN,
                confidence=0.0,
                method=DetectionMethodEnum.DETERMINISTIC,
                status=DetectionStatusEnum.UNKNOWN_VENDOR,
                evidence=evidence_by_vendor[top_vendor],
            )

        # 4. Known Vendor -> Calculate Confidence & Device Type
        confidence = round(min(0.99, top_score / (top_score + 40)), 2)

        # Determine device type
        device_type = DeviceTypeEnum.UNKNOWN
        if top_vendor == VendorEnum.CISCO:
            device_type = detect_cisco_device_type(content)
        elif top_vendor == VendorEnum.JUNIPER:
            device_type = detect_juniper_device_type(content)
        elif top_vendor == VendorEnum.FORTINET:
            device_type = detect_fortinet_device_type(content)

        # Determine status (KNOWN vs AMBIGUOUS)
        status = DetectionStatusEnum.KNOWN
        if second_score > 0 and second_score >= (top_score * 0.7):
            status = DetectionStatusEnum.AMBIGUOUS

        return VendorDetectionResult(
            file_id=file_id,
            relative_path=relative_path,
            vendor=top_vendor,
            device_type=device_type,
            confidence=confidence,
            method=DetectionMethodEnum.DETERMINISTIC,
            status=status,
            evidence=evidence_by_vendor[top_vendor],
        )


vendor_detector = VendorDetector()
