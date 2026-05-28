# AWS Deployment Plan

## Target architecture

- **ECS Fargate** — `api` and `worker` services
- **RDS PostgreSQL** — Multi-AZ in production
- **ElastiCache Redis** — Celery broker
- **ALB** — HTTPS termination, routes `/webhooks/*` and `/api/*`
- **S3 + CloudFront** — frontend static assets
- **Secrets Manager** — GitHub private key, JWT secret, OpenAI key
- **ECR** — container images from GitHub Actions

## Steps

1. Build and push images:
   ```bash
   docker build -t guardpr-api ./backend
   docker tag guardpr-api:latest <account>.dkr.ecr.<region>.amazonaws.com/guardpr-api:latest
   docker push <account>.dkr.ecr.<region>.amazonaws.com/guardpr-api:latest
   ```

2. Create RDS PostgreSQL and ElastiCache Redis; set `DATABASE_URL` and `REDIS_URL` in ECS task definitions.

3. Store secrets in AWS Secrets Manager; reference in task definition `secrets` block.

4. Configure ALB listener rules:
   - `POST /webhooks/github` → api target group
   - `/api/*` → api target group
   - `/*` → CloudFront (frontend)

5. Update GitHub App webhook URL to production ALB domain.

6. Enable CloudWatch logs and alarms on API 5xx, worker failures, and queue depth.

## Production checklist

- [ ] `ENVIRONMENT=production`
- [ ] Strong `JWT_SECRET` and `GITHUB_WEBHOOK_SECRET`
- [ ] HTTPS only
- [ ] WAF rate limiting on webhook endpoint
- [ ] Database backups enabled
- [ ] No debug mode
