# GitHub App Setup

## Create the app

1. Go to **GitHub → Settings → Developer settings → GitHub Apps → New GitHub App**
2. Configure:
   - **Name:** GuardPR AI
   - **Homepage URL:** `http://localhost:5173` (or your production URL)
   - **Webhook URL:** `https://<your-ngrok-or-domain>/webhooks/github`
   - **Webhook secret:** generate a strong random string → set `GITHUB_WEBHOOK_SECRET` in `.env`
3. **Permissions** (least privilege):
   - Repository contents: **Read**
   - Pull requests: **Read and write**
   - Metadata: **Read**
4. **Subscribe to events:**
   - Pull request
   - Installation
   - Installation repositories
5. **Where can this app be installed?** Any account

## Generate credentials

1. Note the **App ID** → `GITHUB_APP_ID`
2. **Generate a private key** → save as `backend/secrets/github-app.pem` (gitignored)
3. Set `GITHUB_APP_PRIVATE_KEY_PATH=/run/secrets/github-app.pem` or mount in Docker

## Install on a repository

1. From the app settings page, click **Install App**
2. Select org/user and repositories
3. Open a test PR — webhook should return `202` and enqueue a scan

## Local development with ngrok

```bash
ngrok http 8000
```

Update the GitHub App webhook URL to the ngrok HTTPS URL + `/webhooks/github`.

Verify delivery in GitHub App → Advanced → Recent Deliveries. Response should be `202`.

## Required environment variables

```bash
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY_PATH=./secrets/github-app.pem
GITHUB_WEBHOOK_SECRET=your-webhook-secret
OPENAI_API_KEY=sk-...          # optional but recommended for AI triage
```
