# GuardPR AI — AI Security Code Review Bot

Production-grade **DevSecOps / Application Security** portfolio project. GuardPR AI is a GitHub App that automatically reviews pull requests for security issues, triages findings with AI, posts PR comments, and tracks results in a web dashboard.

![stack](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-61DAFB?style=flat&logo=react&logoColor=black)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)

## Screenshots
<img width="2550" height="1740" alt="Screenshot 2026-05-28 at 17 24 32" src="https://github.com/user-attachments/assets/3c714b04-f126-4f08-8e61-5ddd9fdf9cff" />
<img width="2880" height="1800" alt="Screenshot 2026-05-28 at 17 25 10" src="https://github.com/user-attachments/assets/61e7a4f1-8374-4f6c-8436-b7061dd596f4" />
<img width="2880" height="1800" alt="Screenshot 2026-05-28 at 17 25 19" src="https://github.com/user-attachments/assets/f9484b8d-ed3d-4cf1-a774-e29bbb467336" />
<img width="2880" height="1800" alt="Screenshot 2026-05-28 at 17 25 30" src="https://github.com/user-attachments/assets/42b066de-c9d6-4fe1-96bc-bb85dfa9b798" />
<img width="2880" height="1800" alt="Screenshot 2026-05-28 at 17 25 35" src="https://github.com/user-attachments/assets/f1059712-cfda-4908-9d36-92e9a71598ce" />
<img width="2880" height="1800" alt="Screenshot 2026-05-28 at 17 25 40" src="https://github.com/user-attachments/assets/087a0454-f2cd-47b2-844b-c5dde7ed93d8" />
<img width="2880" height="1800" alt="Screenshot 2026-05-28 at 17 26 02" src="https://github.com/user-attachments/assets/b6384dec-cbd6-4be4-a866-22262ac109c2" />








## Features

- **GitHub App** — webhooks for `pull_request.opened`, `synchronize`, `reopened`
- **Security scanners** — Semgrep (SAST), Gitleaks (secrets), Trivy & Checkov (optional)
- **AI triage** — OWASP mapping, exploitability scoring, remediation guidance
- **PR comments** — summary + optional inline comments on changed lines
- **Dashboard** — React + TypeScript UI for repos, scans, findings, settings, audit log
- **Reports** — JSON, PDF, SARIF export
- **Policy gate** — block/warn on Critical/High findings
- **Baseline scanning** — suppress legacy issues from main branch
- **Audit logging** — full activity trail

## Architecture

```
GitHub PR event → Webhook (FastAPI) → Celery worker → Scanners → AI triage → PostgreSQL
                                                      ↓
                                              PR comments + Dashboard
```

## Quick start

### 1. Clone and configure

```bash
cd /Users/sahamamjad/projects/guardpr-ai
cp .env.example .env
# Edit .env: GITHUB_APP_ID, GITHUB_WEBHOOK_SECRET, OPENAI_API_KEY, JWT_SECRET
```

### 2. Start with Docker Compose

```bash
make up
make seed   # demo user: admin@guardpr.local / admin123
```

| Service   | URL                    |
|-----------|------------------------|
| API       | http://localhost:8000  |
| API docs  | http://localhost:8000/api/docs |
| Dashboard | http://localhost:5173  |
| Postgres  | localhost:5433         |

### 3. GitHub App setup

See [docs/github-app-setup.md](docs/github-app-setup.md).

For local webhooks:

```bash
ngrok http 8000
# Set webhook URL: https://<ngrok-id>.ngrok.io/webhooks/github
```

### 4. Test a PR scan

1. Install the GitHub App on a test repository
2. Open or update a pull request with code changes
3. Watch the worker logs: `make logs`
4. View results in the dashboard or on the PR comment

## Project structure

```text
guardpr-ai/
├── backend/          # FastAPI, Celery, scanners, AI triage
├── frontend/         # React + TypeScript dashboard
├── demo/             # Intentionally vulnerable sample repos
├── docs/             # Setup and deployment guides
├── docker-compose.yml
└── .github/workflows/ci.yml
```

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/webhooks/github` | GitHub webhook receiver |
| POST | `/api/v1/auth/login` | JWT login |
| GET | `/api/v1/repos` | List repositories |
| GET | `/api/v1/scans/{id}` | Scan details + findings |
| GET | `/api/v1/scans/{id}/report` | Export JSON/PDF |
| GET | `/api/v1/scans/{id}/sarif` | SARIF export |
| POST | `/api/v1/findings/{id}/false-positive` | Mark false positive |
| GET | `/api/v1/audit-logs` | Audit trail |

## Local development (without Docker)

```bash
# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Worker (separate terminal)
celery -A app.workers.celery_app worker -l info

# Frontend
cd frontend && npm install && npm run dev
```

## Security

- GitHub webhook HMAC-SHA256 verification
- Secrets redacted before logs, DB, AI prompts, and PR comments
- JWT authentication for dashboard API
- Rate limiting, security headers, structured logging
- Least-privilege GitHub App permissions

## Demo repositories

See [demo/README.md](demo/README.md) for intentionally vulnerable sample code.

## Roadmap

- [x] MVP: webhook + Semgrep + Gitleaks + AI triage + dashboard
- [x] SARIF/PDF export, policy gate, audit log
- [ ] GitHub OAuth login
- [ ] AWS ECS deployment (see docs/deployment-aws.md)
- [ ] Auto-fix suggestions

## License

MIT
