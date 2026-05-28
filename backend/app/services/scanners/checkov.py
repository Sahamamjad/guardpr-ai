"""Checkov IaC scanner integration (optional)."""

import json
import subprocess
from pathlib import Path

from app.config import get_settings
from app.core.logging import get_logger
from app.services.scanners.base import RawFinding

logger = get_logger(__name__)


class CheckovScanner:
    name = "checkov"

    def scan(self, workspace: Path) -> list[RawFinding]:
        settings = get_settings()
        cmd = ["checkov", "-d", str(workspace), "--framework", "terraform,dockerfile", "--output", "json", "--quiet"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=settings.scanner_timeout_seconds, check=False)
        except FileNotFoundError:
            logger.warning("checkov_not_installed")
            return []
        except subprocess.TimeoutExpired:
            logger.error("checkov_timeout")
            return []

        if not result.stdout.strip():
            return []
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        findings: list[RawFinding] = []
        for failed in payload.get("results", {}).get("failed_checks", []) or []:
            file_path = failed.get("file_path", "")
            if file_path.startswith(str(workspace)):
                file_path = str(Path(file_path).relative_to(workspace))
            findings.append(
                RawFinding(
                    scanner=self.name,
                    rule_id=failed.get("check_id", "checkov"),
                    file_path=file_path,
                    line_start=failed.get("file_line_range", [None])[0] if failed.get("file_line_range") else None,
                    line_end=failed.get("file_line_range", [None, None])[-1] if failed.get("file_line_range") else None,
                    severity=_map_checkov_severity(failed.get("severity", "MEDIUM")),
                    title=failed.get("check_name", "IaC misconfiguration"),
                    description=failed.get("check_result", {}).get("entity", failed.get("resource", "")),
                    raw=failed,
                )
            )
        logger.info("checkov_completed", findings=len(findings))
        return findings


def _map_checkov_severity(sev: str) -> str:
    mapping = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
    return mapping.get(str(sev).upper(), "Medium")
