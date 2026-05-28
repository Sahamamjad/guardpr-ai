"""Scanner base types."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass
class RawFinding:
    scanner: str
    rule_id: str
    file_path: str
    line_start: int | None
    line_end: int | None
    severity: str
    title: str
    description: str
    code_snippet: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class Scanner(Protocol):
    name: str

    def scan(self, workspace: Path) -> list[RawFinding]: ...
