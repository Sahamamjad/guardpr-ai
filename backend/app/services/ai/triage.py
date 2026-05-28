"""LLM-based finding triage."""

import json
import time
from typing import Any

from openai import OpenAI

from app.config import get_settings
from app.core.logging import get_logger
from app.schemas import AITriageSchema
from app.services.ai.prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_user_prompt
from app.services.scanners.base import RawFinding
from app.utils.redaction import redact_secrets

logger = get_logger(__name__)


def _detect_language(file_path: str) -> str:
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    return {
        "py": "python",
        "js": "javascript",
        "ts": "typescript",
        "tsx": "typescript",
        "jsx": "javascript",
        "java": "java",
        "go": "go",
        "tf": "terraform",
    }.get(ext, "unknown")


def triage_finding(raw: RawFinding) -> dict[str, Any] | None:
    settings = get_settings()
    if not settings.ai_triage_enabled or not settings.openai_api_key:
        return _fallback_triage(raw)

    client = OpenAI(api_key=settings.openai_api_key)
    payload = {
        "scanner": raw.scanner,
        "rule_id": raw.rule_id,
        "file_path": raw.file_path,
        "line_start": raw.line_start,
        "description": redact_secrets(raw.description),
        "code_snippet": redact_secrets(raw.code_snippet)[:2000],
        "language": _detect_language(raw.file_path),
    }
    started = time.time()
    try:
        response = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(payload)},
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
        )
        content = response.choices[0].message.content or "{}"
        data = json.loads(content)
        triage = AITriageSchema.model_validate(data)
        latency_ms = int((time.time() - started) * 1000)
        result = triage.model_dump()
        result["_meta"] = {
            "model_name": settings.openai_model,
            "prompt_version": PROMPT_VERSION,
            "tokens_used": response.usage.total_tokens if response.usage else None,
            "latency_ms": latency_ms,
        }
        return result
    except Exception as exc:
        logger.error("ai_triage_failed", error=str(exc), rule=raw.rule_id)
        return _fallback_triage(raw)


def triage_findings(raw_findings: list[RawFinding]) -> list[dict[str, Any] | None]:
    return [triage_finding(f) for f in raw_findings]


def _fallback_triage(raw: RawFinding) -> dict[str, Any]:
    severity = raw.severity if raw.severity in {"Critical", "High", "Medium", "Low", "Info"} else "Medium"
    return {
        "title": raw.title,
        "severity": severity,
        "confidence": "Medium",
        "owasp_category": _guess_owasp(raw),
        "exploitability_score": 5,
        "business_impact": "Potential security impact requires review.",
        "technical_explanation": redact_secrets(raw.description),
        "remediation": "Review the flagged code and apply secure coding best practices.",
        "secure_code_example": "",
        "false_positive_reasoning": "AI triage unavailable; verify manually.",
        "developer_comment": redact_secrets(raw.title),
        "is_likely_false_positive": False,
        "_meta": {"model_name": "fallback", "prompt_version": PROMPT_VERSION, "tokens_used": 0, "latency_ms": 0},
    }


def _guess_owasp(raw: RawFinding) -> str:
    text = f"{raw.rule_id} {raw.title} {raw.description}".lower()
    if "sql" in text or "injection" in text:
        return "A03: Injection"
    if "xss" in text or "cross-site" in text:
        return "A03: Injection"
    if "secret" in text or "password" in text or "token" in text:
        return "A07: Identification and Authentication Failures"
    if "auth" in text:
        return "A07: Identification and Authentication Failures"
    if "ssrf" in text:
        return "A10: Server-Side Request Forgery"
    if "access" in text:
        return "A01: Broken Access Control"
    return "A06: Vulnerable and Outdated Components"
