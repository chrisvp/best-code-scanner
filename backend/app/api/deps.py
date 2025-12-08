"""Authentication and authorization dependencies."""
from datetime import datetime, timezone
from typing import Optional
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.auth_models import User, UserSession, UserRole, UserStatus


def get_db():
    """Database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """
    Get current authenticated user from session cookie.
    Raises 401 if not authenticated, 403 if account not active.
    """
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session = db.query(UserSession).filter(
        UserSession.token == token,
        UserSession.expires_at > datetime.now(timezone.utc)
    ).first()

    if not session:
        raise HTTPException(status_code=401, detail="Session expired or invalid")

    if session.user.status != UserStatus.ACTIVE.value:
        raise HTTPException(status_code=403, detail="Account not active")

    return session.user


async def get_current_user_optional(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """Get current user if logged in, None otherwise. Does not raise exceptions."""
    try:
        return await get_current_user(request, db)
    except HTTPException:
        return None


def require_role(*roles: UserRole):
    """
    Dependency factory for role-based access control.

    Usage:
        @router.get("/admin-only")
        async def admin_endpoint(user: User = Depends(require_role(UserRole.ADMIN))):
            ...
    """
    async def check_role(user: User = Depends(get_current_user)) -> User:
        role_values = [r.value if isinstance(r, UserRole) else r for r in roles]
        if user.role not in role_values:
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of: {', '.join(role_values)}"
            )
        return user
    return check_role


# Convenience dependencies for common role checks
require_admin = require_role(UserRole.ADMIN)
require_developer_or_admin = require_role(UserRole.ADMIN, UserRole.DEVELOPER)
require_any_role = require_role(UserRole.ADMIN, UserRole.DEVELOPER, UserRole.READONLY)
