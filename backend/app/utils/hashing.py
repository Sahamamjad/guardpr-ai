"""Finding fingerprint hashing."""

import hashlib


def finding_fingerprint(scanner: str, rule_id: str, file_path: str, line_start: int | None) -> str:
    raw = f"{scanner}|{rule_id}|{file_path}|{line_start or 0}"
    return hashlib.sha256(raw.encode()).hexdigest()
