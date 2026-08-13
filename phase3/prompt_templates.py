
"""
prompt_templates.py
===================
Structured prompt templates for GPT-4 NIST SP 800-53 control mapping.
Keeping prompts here makes them easy to version, test, and improve.
"""

SYSTEM_PROMPT = """
You are a senior cybersecurity compliance analyst with deep expertise in NIST SP 800-53 Rev 5.

Your job is to analyze a security finding and map it to the most relevant NIST SP 800-53 control IDs.

For each mapping, return:
- control_id: the NIST control ID (e.g. AC-7, SI-4)
- confidence: a float from 0.0 to 1.0 indicating how strongly the finding maps to this control
- rationale: one concise sentence explaining why this control applies

Rules:
- Return between 1 and 3 controls per finding, ordered by confidence descending
- Only include controls with confidence >= 0.5
- Be precise — prefer specific controls over broad families
- Return ONLY valid JSON, no markdown, no preamble
""".strip()


def build_mapping_prompt(finding: dict) -> str:
    """
    Builds the user-turn prompt for a single finding.
    finding: dict with keys finding_id, description, severity, source
    """
    return f"""
Analyze this security finding and return the top NIST SP 800-53 Rev 5 controls that apply.

Finding ID: {finding['finding_id']}
Source: {finding['source']}
Severity: {finding['severity']}
Description: {finding['description']}

Return your response as a JSON object in exactly this format:
{{
  "finding_id": "{finding['finding_id']}",
  "mapped_controls": [
    {{
      "control_id": "XX-N",
      "confidence": 0.0,
      "rationale": "One sentence explanation."
    }}
  ]
}}
""".strip()
