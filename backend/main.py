from fastapi import FastAPI
from contextlib import asynccontextmanager
from typing import Optional
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """App lifespan: setup queue manager scan state checker on startup."""
    from app.services.orchestration.queue_manager import queue_manager
    from app.core.database import SessionLocal
    from app.models.models import Scan
    from app.models.scanner_models import GlobalSetting

    # Load persisted settings from database
    db = SessionLocal()
    try:
        # Ensure default settings exist
        GlobalSetting.ensure_defaults(db)

        saved_base_url = GlobalSetting.get(db, "llm_base_url")
        saved_api_key = GlobalSetting.get(db, "llm_api_key")
        saved_verify_ssl = GlobalSetting.get(db, "llm_verify_ssl")

        if saved_base_url:
            settings.LLM_BASE_URL = saved_base_url
        if saved_api_key:
            settings.LLM_API_KEY = saved_api_key
        if saved_verify_ssl is not None:
            settings.LLM_VERIFY_SSL = saved_verify_ssl
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

from app.api.endpoints import router
from app.api.tuning import router as tuning_router

app.include_router(router)
app.include_router(tuning_router, prefix="/api/v1/tuning", tags=["tuning"])

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
