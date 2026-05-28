"""Fetch changed files from a pull request."""

from dataclasses import dataclass

import httpx

from app.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2"}


@dataclass
class PRFileChange:
    filename: str
    status: str
    patch: str | None
    additions: int
    deletions: int
    raw_url: str | None = None


async def fetch_pr_files(token: str, owner: str, repo: str, pr_number: int) -> list[PRFileChange]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(url, headers=headers, params={"per_page": 100})
        response.raise_for_status()
        data = response.json()

    settings = get_settings()
    changes: list[PRFileChange] = []
    for item in data:
        filename = item.get("filename", "")
        if any(filename.lower().endswith(ext) for ext in BINARY_EXTENSIONS):
            continue
        if item.get("changes", 0) > settings.max_file_size_bytes:
            logger.warning("file_skipped_too_large", file=filename)
            continue
        if item.get("status") == "removed":
            continue
        changes.append(
            PRFileChange(
                filename=filename,
                status=item.get("status", "modified"),
                patch=item.get("patch"),
                additions=item.get("additions", 0),
                deletions=item.get("deletions", 0),
                raw_url=item.get("raw_url"),
            )
        )
    logger.info("pr_files_fetched", count=len(changes), pr=pr_number)
    return changes


async def download_file_content(token: str, raw_url: str) -> str:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.raw"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(raw_url, headers=headers)
        response.raise_for_status()
        return response.text
