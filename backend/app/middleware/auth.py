"""Authentication middleware to inject current user into all requests."""
from datetime import datetime, timezone
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.auth_models import User, UserSession, UserStatus


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware that adds current_user to request.state for all requests."""

    # Paths that don't require authentication
    PUBLIC_PATHS = {
        "/login",
        "/signup",
        "/health",
        "/openapi.json",
        "/docs",
        "/redoc",
    }

    async def dispatch(self, request: Request, call_next):
        # Initialize user as None
        request.state.user = None

        # Try to get user from session cookie
        token = request.cookies.get("session_token")
        if token:
            db: Session = SessionLocal()
            try:
                session = db.query(UserSession).filter(
                    UserSession.token == token,
                    UserSession.expires_at > datetime.now(timezone.utc)
                ).first()

                if session and session.user.status == UserStatus.ACTIVE.value:
                    request.state.user = session.user
                    # Keep the db session attached for lazy loading
                    request.state.db_session = db
            except Exception:
                db.close()

        response = await call_next(request)

        # Close db session if we opened one
        if hasattr(request.state, 'db_session'):
            request.state.db_session.close()

        return response
