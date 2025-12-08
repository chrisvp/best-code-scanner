from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from contextlib import asynccontextmanager
from typing import Optional
import logging

from app.core.config import settings
from app.middleware.auth import AuthMiddleware

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """App lifespan: setup queue manager scan state checker on startup."""
    from app.services.orchestration.queue_manager import queue_manager
    from app.core.database import SessionLocal
    from app.models.models import Scan
    from app.models.scanner_models import GlobalSetting
    from app.models.auth_models import User, UserRole, UserStatus
    from app.core.security import hash_password

    # Load persisted settings from database
    db = SessionLocal()
    try:
        # Ensure default settings exist
        GlobalSetting.ensure_defaults(db)

        # Create default admin user if no users exist
        user_count = db.query(User).count()
        if user_count == 0:
            logger.info("No users found. Creating default admin user...")
            admin = User(
                email="admin",
                display_name="Administrator",
                hashed_password=hash_password("davy"),
                role=UserRole.ADMIN.value,
                status=UserStatus.ACTIVE.value
            )
            db.add(admin)
            db.commit()
            logger.info("Default admin created: email='admin', password='davy'")

        # Load LLM settings from database
        saved_base_url = GlobalSetting.get(db, "llm_base_url")
        saved_api_key = GlobalSetting.get(db, "llm_api_key")
        saved_verify_ssl = GlobalSetting.get(db, "llm_verify_ssl")

        if saved_base_url:
            settings.LLM_BASE_URL = saved_base_url
        if saved_api_key:
            settings.LLM_API_KEY = saved_api_key
        if saved_verify_ssl is not None:
            settings.LLM_VERIFY_SSL = saved_verify_ssl

        # Load Joern settings from database
        saved_joern_image = GlobalSetting.get(db, "joern_docker_image")
        saved_joern_timeout = GlobalSetting.get(db, "joern_timeout")

        if saved_joern_image:
            settings.JOERN_DOCKER_IMAGE = saved_joern_image
        if saved_joern_timeout:
            settings.JOERN_TIMEOUT = int(saved_joern_timeout)
    finally:
        db.close()

    async def check_scan_state(scan_id: int) -> Optional[str]:
        """Check if a scan exists and return its status."""
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            return scan.status if scan else None
        finally:
            db.close()

    queue_manager.set_scan_state_checker(check_scan_state)

    yield  # App runs here

    # Cleanup on shutdown (optional)


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# Add session middleware for cookie-based sessions
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

# Add auth middleware to inject current user into all requests
app.add_middleware(AuthMiddleware)

# Exception handler for 401 Unauthorized -> Redirect to login for HTML requests
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        # Check if request expects HTML
        accept = request.headers.get("Accept", "")
        if "text/html" in accept:
            return RedirectResponse(url="/login", status_code=302)
    
    # Default JSON response for API or other errors
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

from app.api.endpoints import router
from app.api.tuning import router as tuning_router
from app.api.auth import router as auth_router

app.include_router(router)
app.include_router(tuning_router, prefix="/api/v1/tuning", tags=["tuning"])
app.include_router(auth_router, tags=["auth"])

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
