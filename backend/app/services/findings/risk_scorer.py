"""Risk scoring for findings and scans."""

from app.services.scanners.base import RawFinding

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.1}
CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.7, "low": 0.4}


def score_finding(
    severity: str,
    exploitability: int | None,
    confidence: str | None,
    *,
    is_newly_introduced: bool = True,
    file_sensitivity: float = 0.5,
    reachability: float = 0.5,
) -> float:
    sev_w = SEVERITY_WEIGHT.get(severity.lower(), 0.5)
    conf_w = CONFIDENCE_WEIGHT.get((confidence or "medium").lower(), 0.7)
    exploit_w = (exploitability or 5) / 10.0
    new_bonus = 1.0 if is_newly_introduced else 0.3
    score = (
        sev_w * 0.30
        + exploit_w * 0.25
        + conf_w * 0.15
        + file_sensitivity * 0.10
        + reachability * 0.10
        + new_bonus * 0.10
    ) * 100
    return round(min(max(score, 0), 100), 2)


def overall_risk_from_findings(severities: list[str]) -> tuple[str, float]:
    if not severities:
        return "None", 0.0
    counts = {s.lower(): severities.count(s) for s in severities}
    if counts.get("critical", 0):
        return "Critical", 95.0
    if counts.get("high", 0):
        return "High", 80.0
    if counts.get("medium", 0):
        return "Medium", 55.0
    if counts.get("low", 0):
        return "Low", 30.0
    return "Info", 10.0


def severity_breakdown(findings: list[RawFinding | object]) -> dict[str, int]:
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = getattr(f, "severity", "medium").lower()
        if sev in breakdown:
            breakdown[sev] += 1
    return breakdown
