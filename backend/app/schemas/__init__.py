"""Pydantic schemas."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


class AITriageSchema(BaseModel):
    title: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    confidence: Literal["High", "Medium", "Low"]
    owasp_category: str
    exploitability_score: int = Field(ge=1, le=10)
    business_impact: str
    technical_explanation: str
    remediation: str
    secure_code_example: str
    false_positive_reasoning: str
    developer_comment: str
    is_likely_false_positive: bool = False


class RawFindingSchema(BaseModel):
    scanner: str
    rule_id: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    severity: str
    title: str
    description: str
    code_snippet: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: UUID
    email: str
    full_name: str | None
    role: str

    model_config = {"from_attributes": True}


class RepositoryResponse(BaseModel):
    id: UUID
    full_name: str
    default_branch: str
    security_score: float | None
    last_scan_at: datetime | None

    model_config = {"from_attributes": True}


class PullRequestResponse(BaseModel):
    id: UUID
    pr_number: int
    title: str | None
    author_login: str | None
    state: str | None
    github_url: str | None

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: UUID
    scanner_name: str
    rule_id: str | None
    file_path: str
    line_start: int | None
    severity: str
    confidence: str | None
    owasp_category: str | None
    title: str | None
    description: str | None
    remediation: str | None
    secure_code_example: str | None
    status: str
    risk_score: float | None
    exploitability_score: int | None
    is_newly_introduced: bool
    ai_triage: dict | None = None

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: UUID
    status: str
    trigger_event: str | None
    overall_risk: str | None
    overall_risk_score: float | None
    findings_count: dict | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    pull_request: PullRequestResponse | None = None
    findings: list[FindingResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class ScanSummaryResponse(BaseModel):
    id: UUID
    status: str
    overall_risk: str | None
    findings_count: dict | None
    created_at: datetime

    model_config = {"from_attributes": True}


class RepositorySettingsUpdate(BaseModel):
    severity_threshold: str | None = None
    block_on_critical: bool | None = None
    block_on_high: bool | None = None
    enabled_scanners: list[str] | None = None
    ignored_paths: list[str] | None = None
    ai_triage_enabled: bool | None = None
    inline_comments_enabled: bool | None = None
    policy_gate_enabled: bool | None = None


class FalsePositiveRequest(BaseModel):
    reason: str | None = None


class AcceptRiskRequest(BaseModel):
    reason: str | None = None
    expires_at: datetime | None = None


class AuditLogResponse(BaseModel):
    id: UUID
    action: str
    actor_type: str | None
    resource_type: str | None
    resource_id: UUID | None
    metadata: dict | None = Field(alias="metadata_json")
    created_at: datetime

    model_config = {"from_attributes": True, "populate_by_name": True}
