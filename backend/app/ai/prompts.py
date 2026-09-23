"""
N-CASA AI Prompts
=================
System and user prompt templates for AI-assisted unknown vendor configuration analysis
and security finding explanations.
"""

UNKNOWN_VENDOR_SYSTEM_PROMPT = """You are an expert network security configuration analyst.
Your task is to analyze network device configuration files from unknown, unsupported, or legacy vendors.

CRITICAL CONSTRAINTS & RULES:
1. Output ONLY a valid JSON object matching the requested schema. No conversational preamble, markdown headers, or surrounding text.
2. DO NOT hallucinate line numbers or text. Provide exact 1-indexed start and end line numbers for line evidence.
3. If a field cannot be determined from the configuration file text, set its value to null and confidence to 0.0 with an empty evidence list.
4. Redacted values (marked as <REDACTED>) represent sensitive credentials that were removed prior to transmission. Interpret their presence as indication that a credential/secret was configured.
5. DO NOT determine compliance (PASS/FAIL) directly. Simply extract device identity, management services, authentication parameters, interfaces, logging, and NTP configuration.
6. Under no circumstances issue execution commands, remediation scripts, or shell commands.
"""

UNKNOWN_VENDOR_USER_PROMPT_TEMPLATE = """Analyze the following network configuration file (1-indexed lines):

FILE ID: {file_id}
RAW CONFIGURATION TEXT:
{config_text}

Extract the following structured JSON model:
{{
  "vendor_hypothesis": {{
    "name": "<Detected Vendor Name, e.g. Mikrotik, VyOS, HP Enterprise, Arista, Palo Alto, or Unknown>",
    "confidence": 0.0 to 1.0,
    "evidence": [
      {{
        "line_start": <int>,
        "line_end": <int>,
        "text": "<exact line content>",
        "field": "vendor",
        "explanation": "<reasoning>"
      }}
    ]
  }},
  "device_type": {{
    "value": "<Router|Switch|Firewall|Security Appliance|Unknown>",
    "confidence": 0.0 to 1.0,
    "evidence": [...]
  }},
  "identity": {{
    "hostname": {{
      "value": "<hostname string or null>",
      "confidence": 0.0 to 1.0,
      "evidence": [...]
    }}
  }},
  "management": {{
    "ssh_enabled": {{ "value": true|false|null, "confidence": 0.0 to 1.0, "evidence": [...] }},
    "ssh_version": {{ "value": "1"|"2"|"1.99"|null, "confidence": 0.0 to 1.0, "evidence": [...] }},
    "telnet_enabled": {{ "value": true|false|null, "confidence": 0.0 to 1.0, "evidence": [...] }},
    "http_enabled": {{ "value": true|false|null, "confidence": 0.0 to 1.0, "evidence": [...] }},
    "https_enabled": {{ "value": true|false|null, "confidence": 0.0 to 1.0, "evidence": [...] }}
  }},
  "authentication": {{
    "enable_secret_present": {{ "value": true|false|null, "confidence": 0.0 to 1.0, "evidence": [...] }},
    "aaa_enabled": {{ "value": true|false|null, "confidence": 0.0 to 1.0, "evidence": [...] }}
  }},
  "interfaces": [
    {{
      "interface_name": "<interface identifier>",
      "ip_address": {{ "value": "<ip address or null>", "confidence": 0.0 to 1.0, "evidence": [...] }},
      "enabled": {{ "value": true|false|null, "confidence": 0.0 to 1.0, "evidence": [...] }},
      "evidence": [...]
    }}
  ],
  "logging_remote_servers": {{ "value": ["<ip or hostname>", ...]|null, "confidence": 0.0 to 1.0, "evidence": [...] }},
  "ntp_servers": {{ "value": ["<ip or hostname>", ...]|null, "confidence": 0.0 to 1.0, "evidence": [...] }}
}}
"""

FINDING_EXPLANATION_SYSTEM_PROMPT = """You are a senior network security auditing consultant.
Your task is to provide clear, actionable, evidence-referenced explanations for network configuration security findings.

CRITICAL RULES:
1. Output ONLY a valid JSON object matching the requested schema.
2. Focus strictly on explaining the security risk, interpreting the evidence lines, and recommending manual review steps.
3. DO NOT generate automated remediation scripts or execution commands.
4. Refer to line numbers and configuration evidence accurately.
"""

FINDING_EXPLANATION_USER_PROMPT_TEMPLATE = """Provide an AI-assisted explanation for the following security finding:

FINDING DETAILS:
- Finding ID: {finding_id}
- Title: {title}
- Control ID: {control_id}
- Severity: {severity}
- Category: {category}
- Compliance Status: {status}
- Summary: {description}
- Rationale: {rationale}

EVIDENCE LINES:
{evidence_lines_text}

CONFIGURATION CONTEXT (Vendor: {vendor}, Device Type: {device_type}):
{config_snippet}

Output JSON format:
{{
  "finding_id": "{finding_id}",
  "summary": "<Concise summary of why this finding was flagged>",
  "security_impact": "<Technical explanation of security implications and risk>",
  "evidence_interpretation": "<Line-by-line explanation of the configuration evidence>",
  "recommended_review": "<Practical verification and architecture review guidance>",
  "confidence": 0.90
}}
"""
