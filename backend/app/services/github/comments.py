"""Post security review comments on pull requests."""

from uuid import UUID

import httpx

from app.core.logging import get_logger
from app.db.models import Finding
from app.utils.redaction import redact_secrets

logger = get_logger(__name__)

SCAN_MARKER_PREFIX = "<!-- guardpr-scan:"


def build_summary_comment(scan_id: UUID, overall_risk: str, findings: list[Finding], dashboard_url: str) -> str:
    lines = [
        f"{SCAN_MARKER_PREFIX}{scan_id} -->",
        "## GuardPR AI Security Review Summary",
        "",
        f"**Overall PR Risk:** {overall_risk or 'None'}",
        "",
        "### Findings",
    ]
    if not findings:
        lines.append("- No security issues detected in changed files.")
    else:
        grouped: dict[str, int] = {}
        for f in findings:
            if f.status in {"false_positive", "ignored"}:
                continue
            key = f"{f.severity} — {f.title or f.vulnerability_type or f.rule_id}"
            grouped[key] = grouped.get(key, 0) + 1
        for label, count in sorted(grouped.items(), key=lambda x: x[0]):
            suffix = f" (x{count})" if count > 1 else ""
            lines.append(f"- {count} {label}{suffix}")

    high_count = sum(1 for f in findings if f.severity.lower() in {"critical", "high"} and f.status == "open")
    lines.extend(["", "**Recommended Action:**"])
    if high_count:
        lines.append("Fix Critical/High severity issues before merge.")
    else:
        lines.append("Review Medium/Low findings and proceed when acceptable.")

    lines.extend(["", f"[View full report in dashboard]({dashboard_url}/scans/{scan_id})"])
    return redact_secrets("\n".join(lines))


def build_inline_comment(finding: Finding) -> str:
    ai = finding.ai_triage.triage_json if finding.ai_triage else {}
    title = ai.get("title") or finding.title or "Security Finding"
    severity = ai.get("severity") or finding.severity
    confidence = ai.get("confidence") or finding.confidence or "Medium"
    owasp = ai.get("owasp_category") or finding.owasp_category or "N/A"
    exploit = ai.get("exploitability_score") or finding.exploitability_score or "N/A"
    explanation = ai.get("technical_explanation") or finding.description or ""
    remediation = ai.get("remediation") or finding.remediation or ""
    example = ai.get("secure_code_example") or finding.secure_code_example or ""

    body = [
        f"### {severity} Risk: {title}",
        "",
        redact_secrets(explanation),
        "",
        f"**OWASP Mapping:** {owasp}",
        f"**Severity:** {severity}",
        f"**Confidence:** {confidence}",
        f"**Exploitability:** {exploit}/10" if exploit != "N/A" else f"**Exploitability:** {exploit}",
        "",
        "**Suggested Fix:**",
        redact_secrets(remediation),
    ]
    if example:
        body.extend(["", "**Secure Example:**", f"```\n{redact_secrets(example)}\n```"])
    return "\n".join(body)


async def post_pr_comment(token: str, owner: str, repo: str, pr_number: int, body: str) -> int:
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"body": body},
        )
        response.raise_for_status()
        comment_id = response.json()["id"]
        logger.info("pr_comment_posted", pr=pr_number, comment_id=comment_id)
        return comment_id


async def post_inline_comment(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    commit_sha: str,
    file_path: str,
    line: int,
    body: str,
) -> int:
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"body": body, "commit_id": commit_sha, "path": file_path, "line": line, "side": "RIGHT"},
        )
        response.raise_for_status()
        return response.json()["id"]
