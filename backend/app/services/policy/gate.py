"""Repository severity policy gate."""

from app.db.models import Finding, RepositorySettings


def evaluate_policy(settings: RepositorySettings | None, findings: list[Finding]) -> dict:
    settings = settings or RepositorySettings()
    open_findings = [f for f in findings if f.status == "open" and f.is_newly_introduced]
    critical = [f for f in open_findings if (f.severity or "").lower() == "critical"]
    high = [f for f in open_findings if (f.severity or "").lower() == "high"]

    blocked = False
    warnings: list[str] = []
    if settings.block_on_critical and critical:
        blocked = True
        warnings.append(f"{len(critical)} Critical finding(s) require remediation before merge.")
    if settings.block_on_high and high:
        blocked = True
        warnings.append(f"{len(high)} High finding(s) require remediation before merge.")

    return {
        "blocked": blocked,
        "warnings": warnings,
        "critical_count": len(critical),
        "high_count": len(high),
    }
