# Demo Repositories

Intentionally vulnerable sample code for GuardPR AI scanner validation.

| Repo | Expected findings |
|------|-------------------|
| `vulnerable-flask-api` | SQL injection, XSS |
| `vulnerable-node-api` | Command injection, broken access control |
| `insecure-dockerfile` | Root user, missing hardening |
| `insecure-terraform-aws` | Public S3 ACL, open security group |
| `fake-secrets-repo` | Hardcoded secrets (Gitleaks) |

Run locally:

```bash
cd demo/vulnerable-flask-api
semgrep scan --config=p/owasp-top-ten .
```
