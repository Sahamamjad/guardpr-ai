"""Normalize and deduplicate scanner findings."""

from app.services.scanners.base import RawFinding
from app.utils.hashing import finding_fingerprint
from app.utils.redaction import redact_dict_values, redact_secrets


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def normalize_findings(findings: list[RawFinding]) -> list[RawFinding]:
    normalized: list[RawFinding] = []
    for f in findings:
        normalized.append(
            RawFinding(
                scanner=f.scanner,
                rule_id=f.rule_id or "unknown",
                file_path=f.file_path.lstrip("./"),
                line_start=f.line_start,
                line_end=f.line_end,
                severity=_normalize_severity(f.severity),
                title=redact_secrets(f.title),
                description=redact_secrets(f.description),
                code_snippet=redact_secrets(f.code_snippet),
                raw=redact_dict_values(f.raw),
            )
        )
    return normalized


def deduplicate_findings(findings: list[RawFinding]) -> list[RawFinding]:
    seen: set[str] = set()
    unique: list[RawFinding] = []
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity.lower(), 99)):
        fp = finding_fingerprint(f.scanner, f.rule_id, f.file_path, f.line_start)
        if fp in seen:
            continue
        seen.add(fp)
        unique.append(f)
    return unique


def _normalize_severity(severity: str) -> str:
    s = (severity or "Medium").strip().capitalize()
    if s.lower() == "error":
        return "High"
    return s if s in {"Critical", "High", "Medium", "Low", "Info"} else "Medium"
