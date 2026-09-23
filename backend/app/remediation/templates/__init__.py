"""
N-CASA Remediation Templates Package
======================================
Vendor-specific remediation template implementations.
"""

from app.remediation.templates.base import BaseRemediationTemplate
from app.remediation.templates.cisco import (
    CiscoAAARemediation,
    CiscoHTTPRemediation,
    CiscoHTTPSRemediation,
    CiscoManualReviewRemediation,
    CiscoSSHRemediation,
    CiscoTelnetRemediation,
)
from app.remediation.templates.fortinet import (
    FortinetHTTPRemediation,
    FortinetManualReviewRemediation,
    FortinetTelnetRemediation,
)
from app.remediation.templates.juniper import (
    JuniperHTTPRemediation,
    JuniperHTTPSRemediation,
    JuniperManualReviewRemediation,
    JuniperSSHRemediation,
    JuniperTelnetRemediation,
)

__all__ = [
    "BaseRemediationTemplate",
    "CiscoAAARemediation",
    "CiscoHTTPRemediation",
    "CiscoHTTPSRemediation",
    "CiscoManualReviewRemediation",
    "CiscoSSHRemediation",
    "CiscoTelnetRemediation",
    "FortinetHTTPRemediation",
    "FortinetManualReviewRemediation",
    "FortinetTelnetRemediation",
    "JuniperHTTPRemediation",
    "JuniperHTTPSRemediation",
    "JuniperManualReviewRemediation",
    "JuniperSSHRemediation",
    "JuniperTelnetRemediation",
]
