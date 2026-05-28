"""FastAPI dependencies."""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.exceptions import UnauthorizedError
from app.core.security import decode_access_token
from app.db.models import User
from app.db.session import get_db

security = HTTPBearer(auto_error=False)


def get_current_user(
    db: Annotated[Session, Depends(get_db)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
) -> User:
    if credentials is None:
        raise UnauthorizedError("Missing authentication token")
    user_id = decode_access_token(credentials.credentials)
    user = db.query(User).filter(User.id == UUID(user_id), User.is_active.is_(True)).first()
    if not user:
        raise UnauthorizedError("User not found")
    return user
