"""Secret redaction utilities."""

import re

SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|authorization)\s*[:=]\s*['\"]?[\w\-./+=]{8,}"),
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgho_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bghu_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bghs_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bghr_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
]

REDACTED = "[REDACTED]"


def redact_secrets(text: str) -> str:
    if not text:
        return text
    result = text
    for pattern in SECRET_PATTERNS:
        result = pattern.sub(REDACTED, result)
    return result


def redact_dict_values(data: dict, keys_to_redact: set[str] | None = None) -> dict:
    sensitive_keys = keys_to_redact or {"secret", "token", "password", "api_key", "authorization", "private_key"}
    cleaned = {}
    for key, value in data.items():
        if key.lower() in sensitive_keys:
            cleaned[key] = REDACTED
        elif isinstance(value, str):
            cleaned[key] = redact_secrets(value)
        elif isinstance(value, dict):
            cleaned[key] = redact_dict_values(value, sensitive_keys)
        elif isinstance(value, list):
            cleaned[key] = [
                redact_dict_values(v, sensitive_keys) if isinstance(v, dict) else redact_secrets(v) if isinstance(v, str) else v
                for v in value
            ]
        else:
            cleaned[key] = value
    return cleaned
