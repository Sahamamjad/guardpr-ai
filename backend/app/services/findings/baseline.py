"""Baseline comparison to avoid re-reporting legacy issues."""

from sqlalchemy.orm import Session

from app.db.models import Finding, Scan
from app.utils.hashing import finding_fingerprint


def get_baseline_fingerprints(db: Session, repository_id) -> set[str]:
    baseline_scan = (
        db.query(Scan)
        .join(Scan.pull_request)
        .filter(Scan.is_baseline.is_(True), Scan.pull_request.has(repository_id=repository_id))
        .order_by(Scan.created_at.desc())
        .first()
    )
    if not baseline_scan:
        return set()
    findings = db.query(Finding).filter(Finding.scan_id == baseline_scan.id).all()
    return {f.fingerprint for f in findings}


def mark_baseline_findings(db: Session, scan_id, repository_id, raw_findings) -> None:
    baseline_fps = get_baseline_fingerprints(db, repository_id)
    if not baseline_fps:
        return
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    for finding in findings:
        if finding.fingerprint in baseline_fps:
            finding.exists_in_baseline = True
            finding.is_newly_introduced = False
    db.commit()


def fingerprint_for_raw(raw) -> str:
    return finding_fingerprint(raw.scanner, raw.rule_id, raw.file_path, raw.line_start)
