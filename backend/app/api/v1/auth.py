"""Authentication API."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.exceptions import UnauthorizedError
from app.core.security import create_access_token, hash_password, verify_password
from app.db.models import User
from app.db.session import get_db
from app.schemas import LoginRequest, TokenResponse, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Annotated[Session, Depends(get_db)]):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not user.password_hash or not verify_password(payload.password, user.password_hash):
        raise UnauthorizedError("Invalid email or password")
    token = create_access_token(str(user.id))
    return TokenResponse(access_token=token)


@router.post("/register", response_model=UserResponse)
def register(payload: LoginRequest, db: Annotated[Session, Depends(get_db)]):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        from app.core.exceptions import AppError

        raise AppError("Email already registered", status_code=409)
    user = User(email=payload.email, password_hash=hash_password(payload.password), full_name=payload.email.split("@")[0])
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
