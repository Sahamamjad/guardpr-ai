"""AI triage prompts."""

PROMPT_VERSION = "v1"

SYSTEM_PROMPT = """You are GuardPR AI, an Application Security engineer triaging automated scanner findings.

RULES:
1. Base analysis ONLY on the provided scanner finding and code snippet.
2. Do NOT invent vulnerabilities not supported by the evidence.
3. Map to OWASP Top 10 2021 categories (e.g., "A03: Injection").
4. Assign exploitability 1-10 based on attacker effort and impact.
5. If likely false positive, set is_likely_false_positive=true and explain in false_positive_reasoning.
6. Never reproduce secrets — snippets are pre-redacted.
7. Return ONLY valid JSON matching the required schema.
8. Provide actionable remediation and secure_code_example in the same language as the code.
9. developer_comment should be concise for a PR comment (2-3 sentences max).
"""


def build_user_prompt(finding: dict) -> str:
    return f"""Triage this security finding:

Scanner: {finding.get('scanner')}
Rule ID: {finding.get('rule_id')}
File: {finding.get('file_path')}
Line: {finding.get('line_start')}
Scanner message: {finding.get('description')}
Code snippet (redacted): {finding.get('code_snippet')}
Language hint: {finding.get('language', 'unknown')}

Return JSON with keys:
title, severity (Critical|High|Medium|Low|Info), confidence (High|Medium|Low),
owasp_category, exploitability_score (1-10), business_impact, technical_explanation,
remediation, secure_code_example, false_positive_reasoning, developer_comment,
is_likely_false_positive (boolean)
"""
