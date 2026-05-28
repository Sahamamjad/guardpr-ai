"""Initial schema."""

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Tables created via Base.metadata.create_all in dev; use autogenerate for production migrations.
    pass


def downgrade() -> None:
    pass
