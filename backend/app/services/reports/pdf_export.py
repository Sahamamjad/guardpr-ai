"""PDF report export."""

from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from sqlalchemy.orm import Session

from app.db.models import Finding, Scan, ScanReport
from app.utils.redaction import redact_secrets


def generate_pdf_report(db: Session, scan: Scan, storage_dir: Path) -> ScanReport:
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    pr = scan.pull_request
    repo = pr.repository if pr else None

    storage_dir.mkdir(parents=True, exist_ok=True)
    path = storage_dir / f"{scan.id}.pdf"

    c = canvas.Canvas(str(path), pagesize=letter)
    width, height = letter
    y = height - inch

    def line(text: str, indent: float = 0):
        nonlocal y
        if y < inch:
            c.showPage()
            y = height - inch
        c.drawString(inch + indent, y, text[:100])
        y -= 14

    line("GuardPR AI Security Report")
    line(f"Repository: {repo.full_name if repo else 'N/A'}")
    line(f"PR: #{pr.pr_number if pr else 'N/A'}")
    line(f"Scan ID: {scan.id}")
    line(f"Overall Risk: {scan.overall_risk or 'None'}")
    line("")
    line("Findings:")
    for f in findings[:50]:
        line(f"- [{f.severity}] {redact_secrets(f.title or f.rule_id or 'Finding')} ({f.file_path}:{f.line_start})")
    line("")
    line("Recommended: Review Critical/High issues before merge.")

    c.save()
    record = ScanReport(scan_id=scan.id, format="pdf", storage_path=str(path))
    db.add(record)
    db.flush()
    return record
