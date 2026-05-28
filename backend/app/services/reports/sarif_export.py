"""SARIF export for GitHub Code Scanning."""

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.db.models import Finding, Scan, ScanReport
from app.utils.redaction import redact_secrets

SARIF_VERSION = "2.1.0"


def generate_sarif_report(db: Session, scan: Scan, storage_dir: Path) -> ScanReport:
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    rules = {}
    results = []

    for f in findings:
        rule_id = f.rule_id or f.scanner_name
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": redact_secrets(f.title or rule_id)},
                "fullDescription": {"text": redact_secrets(f.description or "")},
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": redact_secrets(f.title or f.description or "Security finding")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": f.line_start or 1},
                        }
                    }
                ],
                "properties": {
                    "scanner": f.scanner_name,
                    "owasp_category": f.owasp_category,
                    "exploitability_score": f.exploitability_score,
                    "status": f.status,
                },
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GuardPR AI",
                        "informationUri": "https://github.com/guardpr-ai",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    storage_dir.mkdir(parents=True, exist_ok=True)
    path = storage_dir / f"{scan.id}.sarif.json"
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    record = ScanReport(scan_id=scan.id, format="sarif", storage_path=str(path))
    db.add(record)
    db.flush()
    return record


def _sarif_level(severity: str) -> str:
    mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    return mapping.get((severity or "medium").lower(), "warning")
