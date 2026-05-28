"""Orchestrate security scanners on a workspace."""

from pathlib import Path

from app.core.logging import get_logger
from app.services.findings.normalizer import deduplicate_findings, normalize_findings
from app.services.scanners.base import RawFinding
from app.services.scanners.checkov import CheckovScanner
from app.services.scanners.gitleaks import GitleaksScanner
from app.services.scanners.semgrep import SemgrepScanner
from app.services.scanners.trivy import TrivyScanner

logger = get_logger(__name__)

SCANNER_REGISTRY = {
    "semgrep": SemgrepScanner,
    "gitleaks": GitleaksScanner,
    "trivy": TrivyScanner,
    "checkov": CheckovScanner,
}


class ScanOrchestrator:
    def __init__(self, enabled_scanners: list[str] | None = None, ignored_paths: list[str] | None = None):
        self.enabled_scanners = enabled_scanners or ["semgrep", "gitleaks"]
        self.ignored_paths = ignored_paths or []

    def run(self, workspace: Path) -> list[RawFinding]:
        self._filter_ignored_paths(workspace)
        results: list[RawFinding] = []
        for name in self.enabled_scanners:
            scanner_cls = SCANNER_REGISTRY.get(name)
            if not scanner_cls:
                logger.warning("unknown_scanner", scanner=name)
                continue
            scanner = scanner_cls()
            try:
                results.extend(scanner.scan(workspace))
            except Exception as exc:
                logger.error("scanner_failed", scanner=name, error=str(exc))
        normalized = normalize_findings(results)
        return deduplicate_findings(normalized)

    def _filter_ignored_paths(self, workspace: Path) -> None:
        if not self.ignored_paths:
            return
        for file_path in list(workspace.rglob("*")):
            if not file_path.is_file():
                continue
            rel = str(file_path.relative_to(workspace))
            if any(rel.startswith(p.rstrip("/")) or p in rel for p in self.ignored_paths):
                file_path.unlink(missing_ok=True)
