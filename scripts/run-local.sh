#!/usr/bin/env bash
# Run GuardPR AI locally WITHOUT Docker
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Starting PostgreSQL and Redis (Homebrew services)"
brew services start postgresql@16 2>/dev/null || true
brew services start redis 2>/dev/null || true
sleep 2

echo "==> Creating database if needed"
export PATH="/opt/homebrew/opt/postgresql@16/bin:$PATH"
if ! psql -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw guardpr; then
  createuser guardpr 2>/dev/null || true
  createdb -O guardpr guardpr 2>/dev/null || psql postgres -c "CREATE DATABASE guardpr OWNER guardpr;" 2>/dev/null || true
fi

mkdir -p backend/storage/reports

echo ""
echo "=============================================="
echo "  GuardPR AI — run these in SEPARATE terminals"
echo "=============================================="
echo ""
echo "Terminal 1 — API:"
echo "  cd $ROOT/backend && source .venv/bin/activate && uvicorn app.main:app --reload --port 8000"
echo ""
echo "Terminal 2 — Worker:"
echo "  cd $ROOT/backend && source .venv/bin/activate && celery -A app.workers.celery_app worker -l info"
echo ""
echo "Terminal 3 — Frontend:"
echo "  cd $ROOT/frontend && npm run dev"
echo ""
echo "First time only — seed demo user:"
echo "  cd $ROOT/backend && source .venv/bin/activate && python scripts/seed_demo_data.py"
echo ""
echo "Then open: http://localhost:5173"
echo "Login: admin@guardpr.local / admin123"
echo ""
