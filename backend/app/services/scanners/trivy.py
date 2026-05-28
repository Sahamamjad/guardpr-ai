"""Trivy dependency and misconfiguration scanner (optional)."""

import json
import subprocess
from pathlib import Path

from app.config import get_settings
from app.core.logging import get_logger
from app.services.scanners.base import RawFinding

logger = get_logger(__name__)


class TrivyScanner:
    name = "trivy"

    def scan(self, workspace: Path) -> list[RawFinding]:
        settings = get_settings()
        cmd = ["trivy", "fs", "--scanners", "vuln,secret,misconfig", "--format", "json", str(workspace)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=settings.scanner_timeout_seconds, check=False)
        except FileNotFoundError:
            logger.warning("trivy_not_installed")
            return []
        except subprocess.TimeoutExpired:
            logger.error("trivy_timeout")
            return []

        if not result.stdout.strip():
            return []
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        findings: list[RawFinding] = []
        for result_item in payload.get("Results", []):
            target = result_item.get("Target", "")
            rel = str(Path(target).relative_to(workspace)) if target.startswith(str(workspace)) else target
            for vuln in result_item.get("Vulnerabilities", []) or []:
                findings.append(
                    RawFinding(
                        scanner=self.name,
                        rule_id=vuln.get("VulnerabilityID", "CVE"),
                        file_path=rel,
                        line_start=None,
                        line_end=None,
                        severity=_map_trivy_severity(vuln.get("Severity", "UNKNOWN")),
                        title=vuln.get("Title", vuln.get("VulnerabilityID", "Vulnerability")),
                        description=vuln.get("Description", ""),
                        raw=vuln,
                    )
                )
            for misconfig in result_item.get("Misconfigurations", []) or []:
                findings.append(
                    RawFinding(
                        scanner=self.name,
                        rule_id=misconfig.get("ID", "misconfig"),
                        file_path=rel,
                        line_start=misconfig.get("CauseMetadata", {}).get("StartLine"),
                        line_end=misconfig.get("CauseMetadata", {}).get("EndLine"),
                        severity=_map_trivy_severity(misconfig.get("Severity", "MEDIUM")),
                        title=misconfig.get("Title", "Misconfiguration"),
                        description=misconfig.get("Description", misconfig.get("Message", "")),
                        raw=misconfig,
                    )
                )
        logger.info("trivy_completed", findings=len(findings))
        return findings


def _map_trivy_severity(sev: str) -> str:
    mapping = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Info"}
    return mapping.get(sev.upper(), "Medium")
