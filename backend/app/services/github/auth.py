"""GitHub App JWT and installation access tokens."""

import time

import httpx
import jwt

from app.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def create_app_jwt() -> str:
    settings = get_settings()
    private_key = settings.github_private_key
    if not settings.github_app_id or not private_key:
        raise RuntimeError("GitHub App credentials are not configured")

    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": settings.github_app_id}
    return jwt.encode(payload, private_key, algorithm="RS256")


async def get_installation_token(installation_id: int) -> str:
    app_jwt = create_app_jwt()
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        response.raise_for_status()
        token = response.json()["token"]
        logger.info("installation_token_issued", installation_id=installation_id)
        return token
