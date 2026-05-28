"""Application configuration via environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = "development"
    log_level: str = "INFO"
    demo_mode: bool = False

    database_url: str = "postgresql://guardpr:guardpr@localhost:5432/guardpr"
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    github_app_id: str = ""
    github_app_private_key_path: str = ""
    github_webhook_secret: str = ""

    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    ai_triage_enabled: bool = True

    jwt_secret: str = "dev-secret-change-in-production-min-32-chars"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440

    frontend_url: str = "http://localhost:5173"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    rate_limit_per_minute: int = 100

    scanner_timeout_seconds: int = 120
    max_file_size_bytes: int = 1_048_576
    semgrep_configs: str = "p/owasp-top-ten,p/python,p/javascript"

    report_storage_path: str = "/app/storage/reports"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def github_private_key(self) -> str:
        path = Path(self.github_app_private_key_path)
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")

    @property
    def semgrep_config_list(self) -> list[str]:
        return [c.strip() for c in self.semgrep_configs.split(",") if c.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
