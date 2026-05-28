"""Gitleaks secret detection integration."""

import json
import subprocess
import tempfile
from pathlib import Path

from app.config import get_settings
from app.core.logging import get_logger
from app.services.scanners.base import RawFinding
from app.utils.redaction import REDACTED

logger = get_logger(__name__)


class GitleaksScanner:
    name = "gitleaks"

    def scan(self, workspace: Path) -> list[RawFinding]:
        settings = get_settings()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        cmd = [
            "gitleaks",
            "detect",
            "--source",
            str(workspace),
            "--report-format",
            "json",
            "--report-path",
            report_path,
            "--no-git",
            "--exit-code",
            "0",
        ]

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=settings.scanner_timeout_seconds, check=False)
        except FileNotFoundError:
            logger.warning("gitleaks_not_installed")
            return []
        except subprocess.TimeoutExpired:
            logger.error("gitleaks_timeout")
            return []

        report_file = Path(report_path)
        if not report_file.exists():
            return []

        try:
            payload = json.loads(report_file.read_text(encoding="utf-8") or "[]")
        except json.JSONDecodeError:
            return []
        finally:
            report_file.unlink(missing_ok=True)

        findings: list[RawFinding] = []
        for item in payload:
            rel_path = item.get("File", "")
            if rel_path.startswith(str(workspace)):
                rel_path = str(Path(rel_path).relative_to(workspace))
            findings.append(
                RawFinding(
                    scanner=self.name,
                    rule_id=item.get("RuleID", "secret"),
                    file_path=rel_path,
                    line_start=item.get("StartLine"),
                    line_end=item.get("EndLine"),
                    severity="High",
                    title=f"Hardcoded secret: {item.get('Description', item.get('RuleID', 'secret'))}",
                    description=item.get("Description", "Potential secret detected"),
                    code_snippet=REDACTED,
                    raw={**item, "Secret": REDACTED, "Match": REDACTED},
                )
            )
        logger.info("gitleaks_completed", findings=len(findings))
        return findings
