"""Semgrep SAST scanner integration."""

import json
import subprocess
from pathlib import Path

from app.config import get_settings
from app.core.logging import get_logger
from app.services.scanners.base import RawFinding
from app.utils.redaction import redact_secrets

logger = get_logger(__name__)

SEVERITY_MAP = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
}


class SemgrepScanner:
    name = "semgrep"

    def scan(self, workspace: Path) -> list[RawFinding]:
        settings = get_settings()
        cmd = ["semgrep", "scan", "--json", "--quiet"]
        for config in settings.semgrep_config_list:
            cmd.extend(["--config", config])
        cmd.append(str(workspace))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.scanner_timeout_seconds,
                check=False,
            )
        except FileNotFoundError:
            logger.warning("semgrep_not_installed")
            return []
        except subprocess.TimeoutExpired:
            logger.error("semgrep_timeout")
            return []

        if not result.stdout.strip():
            return []

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.error("semgrep_invalid_json", stderr=result.stderr[:500])
            return []

        findings: list[RawFinding] = []
        for item in payload.get("results", []):
            extra = item.get("extra", {})
            start = item.get("start", {})
            end = item.get("end", {})
            path = item.get("path", "")
            rel_path = str(Path(path).relative_to(workspace)) if path.startswith(str(workspace)) else path
            findings.append(
                RawFinding(
                    scanner=self.name,
                    rule_id=item.get("check_id", "unknown"),
                    file_path=rel_path,
                    line_start=start.get("line"),
                    line_end=end.get("line"),
                    severity=SEVERITY_MAP.get(extra.get("severity", "WARNING"), "Medium"),
                    title=extra.get("message", item.get("check_id", "Semgrep finding")),
                    description=extra.get("message", ""),
                    code_snippet=redact_secrets(item.get("extra", {}).get("lines", "")),
                    raw=item,
                )
            )
        logger.info("semgrep_completed", findings=len(findings))
        return findings
