.PHONY: up down logs test seed migrate

up:
	cp -n .env.example .env 2>/dev/null || true
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f api worker

test:
	cd backend && python -m pytest tests -q

seed:
	docker compose exec api python scripts/seed_demo_data.py

migrate:
	docker compose exec api alembic upgrade head
