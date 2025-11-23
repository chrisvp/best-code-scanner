from fastapi import APIRouter, Depends, Request, Form, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.database import get_db, engine, Base, SessionLocal
from app.models.models import Scan, Finding
from app.models.scanner_models import (
    ModelConfig, ScanConfig, ScanFile, ScanFileChunk,
    DraftFinding, VerifiedFinding
)

# Create tables
Base.metadata.create_all(bind=engine)

router = APIRouter()
from pathlib import Path

# Fix template path to be absolute relative to this file
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Custom filter to strip markdown code blocks
def strip_code_blocks(text):
    if not text:
        return text
    text = text.strip()
    # Remove opening code fence with optional language
    if text.startswith('```'):
        first_newline = text.find('\n')
        if first_newline != -1:
            text = text[first_newline + 1:]
        else:
            text = text[3:]
    # Remove closing code fence
    if text.rstrip().endswith('```'):
        text = text.rstrip()[:-3]
    return text.strip()

templates.env.filters['strip_code'] = strip_code_blocks


# Pipeline runner
async def run_pipeline(scan_id: int):
    """Run the scanning pipeline in background"""
    from app.services.orchestration.pipeline import ScanPipeline

    db = SessionLocal()
    try:
        # Update status
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        scan.status = "running"
        db.commit()

        # Get config
        config = db.query(ScanConfig).filter(ScanConfig.scan_id == scan_id).first()

        # Run pipeline
        pipeline = ScanPipeline(scan_id, config, db)
        await pipeline.run()

        # Update status
        scan.status = "completed"
        db.commit()

    except Exception as e:
        import traceback
        print(f"Pipeline error: {traceback.format_exc()}")
        db.rollback()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            scan.status = "failed"
            scan.logs = (scan.logs or "") + f"\nError: {str(e)}"
            db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "scans": scans})


@router.post("/scan/start")
async def start_scan(
    background_tasks: BackgroundTasks,
    target_url: str = Form(...),
    analysis_mode: str = Form("primary_verifiers"),
    scope: str = Form("full"),
    scanner_concurrency: int = Form(20),
    verifier_concurrency: int = Form(10),
    enricher_concurrency: int = Form(5),
    # Performance optimization options
    multi_model_scan: bool = Form(False),  # Use single model for faster initial scan
    min_votes_to_verify: int = Form(1),  # Skip drafts with fewer votes
    deduplicate_drafts: bool = Form(True),  # Merge duplicate findings
    batch_size: int = Form(10),  # Batch size for LLM calls
    chunk_size: int = Form(3000),  # Max tokens per chunk (larger for long-context models)
    db: Session = Depends(get_db)
):
    # Create Scan Record
    new_scan = Scan(target_url=target_url, status="queued")
    db.add(new_scan)
    db.flush()

    # Create Scan Config
    config = ScanConfig(
        scan_id=new_scan.id,
        analysis_mode=analysis_mode,
        scope=scope,
        scanner_concurrency=scanner_concurrency,
        verifier_concurrency=verifier_concurrency,
        enricher_concurrency=enricher_concurrency,
        multi_model_scan=multi_model_scan,
        min_votes_to_verify=min_votes_to_verify,
        deduplicate_drafts=deduplicate_drafts,
        batch_size=batch_size,
        chunk_size=chunk_size
    )
    db.add(config)
    db.commit()

    # Trigger Background Task
    background_tasks.add_task(run_pipeline, new_scan.id)

    # Return updated list via HTMX
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return templates.TemplateResponse("partials/scan_list.html", {"request": {}, "scans": scans})


@router.get("/scan/{scan_id}")
async def get_scan_details(request: Request, scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    return templates.TemplateResponse("partials/scan_details.html", {"request": request, "scan": scan})


@router.get("/scan/{scan_id}/progress")
async def get_progress(request: Request, scan_id: int, db: Session = Depends(get_db)):
    """Get detailed scan progress"""
    # Chunk progress
    total_chunks = db.query(ScanFileChunk).join(ScanFile).filter(
        ScanFile.scan_id == scan_id
    ).count()

    scanned_chunks = db.query(ScanFileChunk).join(ScanFile).filter(
        ScanFile.scan_id == scan_id,
        ScanFileChunk.status == "scanned"
    ).count()

    # Draft progress
    total_drafts = db.query(DraftFinding).filter(
        DraftFinding.scan_id == scan_id
    ).count()

    verified_drafts = db.query(DraftFinding).filter(
        DraftFinding.scan_id == scan_id,
        DraftFinding.status == "verified"
    ).count()

    rejected_drafts = db.query(DraftFinding).filter(
        DraftFinding.scan_id == scan_id,
        DraftFinding.status == "rejected"
    ).count()

    pending_drafts = db.query(DraftFinding).filter(
        DraftFinding.scan_id == scan_id,
        DraftFinding.status == "pending"
    ).count()

    # Final findings (from VerifiedFinding table)
    total_findings = db.query(VerifiedFinding).filter(
        VerifiedFinding.scan_id == scan_id,
        VerifiedFinding.status == "complete"
    ).count()

    # By severity (use adjusted_severity from VerifiedFinding)
    findings_by_severity = {}
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Weakness']:
        count = db.query(VerifiedFinding).filter(
            VerifiedFinding.scan_id == scan_id,
            VerifiedFinding.status == "complete",
            VerifiedFinding.adjusted_severity == severity
        ).count()
        findings_by_severity[severity.lower()] = count

    progress = {
        "scan_id": scan_id,
        "chunks": {
            "total": total_chunks,
            "scanned": scanned_chunks,
            "percent": round((scanned_chunks / total_chunks * 100), 1) if total_chunks else 0
        },
        "drafts": {
            "total": total_drafts,
            "verified": verified_drafts,
            "rejected": rejected_drafts,
            "pending": pending_drafts
        },
        "findings": {
            "total": total_findings,
            "by_severity": findings_by_severity
        }
    }

    # Return HTML for HTMX requests
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/progress.html", {
            "request": request,
            "progress": progress
        })

    return progress


@router.post("/scan/{scan_id}/pause")
async def pause_scan(scan_id: int, db: Session = Depends(get_db)):
    """Pause a running scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan and scan.status == "running":
        scan.status = "paused"
        db.commit()
        return {"status": "paused", "scan_id": scan_id}
    return {"error": "Cannot pause scan", "current_status": scan.status if scan else None}


@router.post("/scan/{scan_id}/resume")
async def resume_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Resume a paused scan"""
    from app.services.orchestration.checkpoint import ScanCheckpoint

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan and scan.status == "paused":
        # Recover checkpoint
        checkpoint = ScanCheckpoint(scan_id, db)
        checkpoint.recover()

        scan.status = "running"
        db.commit()

        # Restart pipeline
        background_tasks.add_task(run_pipeline, scan_id)
        return {"status": "resumed", "scan_id": scan_id}
    return {"error": "Cannot resume scan", "current_status": scan.status if scan else None}


# Model configuration endpoints
@router.get("/models")
async def list_models(db: Session = Depends(get_db)):
    """List all configured models"""
    models = db.query(ModelConfig).all()
    return [
        {
            "id": m.id,
            "name": m.name,
            "base_url": m.base_url,
            "max_concurrent": m.max_concurrent,
            "votes": m.votes,
            "is_analyzer": m.is_analyzer,
            "is_verifier": m.is_verifier
        }
        for m in models
    ]


@router.post("/models")
async def create_model(
    name: str = Form(...),
    base_url: str = Form(...),
    api_key: str = Form(...),
    max_tokens: int = Form(4096),
    max_concurrent: int = Form(2),
    votes: int = Form(1),
    chunk_size: int = Form(3000),
    is_analyzer: bool = Form(False),
    is_verifier: bool = Form(False),
    db: Session = Depends(get_db)
):
    """Create a new model configuration"""
    model = ModelConfig(
        name=name,
        base_url=base_url,
        api_key=api_key,
        max_tokens=max_tokens,
        max_concurrent=max_concurrent,
        votes=votes,
        chunk_size=chunk_size,
        is_analyzer=is_analyzer,
        is_verifier=is_verifier
    )
    db.add(model)
    db.commit()
    db.refresh(model)
    return {"id": model.id, "name": model.name, "status": "created"}


@router.put("/models/{model_id}")
async def update_model(
    model_id: int,
    max_concurrent: int = Form(None),
    votes: int = Form(None),
    is_analyzer: bool = Form(None),
    is_verifier: bool = Form(None),
    db: Session = Depends(get_db)
):
    """Update a model configuration"""
    model = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
    if not model:
        return {"error": "Model not found"}

    if max_concurrent is not None:
        model.max_concurrent = max_concurrent
    if votes is not None:
        model.votes = votes
    if is_analyzer is not None:
        model.is_analyzer = is_analyzer
    if is_verifier is not None:
        model.is_verifier = is_verifier

    db.commit()
    return {"id": model.id, "name": model.name, "status": "updated"}


@router.delete("/models/{model_id}")
async def delete_model(model_id: int, db: Session = Depends(get_db)):
    """Delete a model configuration"""
    model = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
    if not model:
        return {"error": "Model not found"}

    db.delete(model)
    db.commit()
    return {"status": "deleted", "id": model_id}


# Keep existing endpoints
from fastapi.responses import StreamingResponse
# from app.services.report_service import report_service  # TODO: install xhtml2pdf


@router.post("/finding/{finding_id}/generate-fix", response_class=HTMLResponse)
async def generate_fix(finding_id: int, db: Session = Depends(get_db)):
    """Generate a fix for a finding on-demand"""
    from app.services.analysis.enricher import FindingEnricher
    from app.services.orchestration.model_orchestrator import ModelOrchestrator

    # Get the finding
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return HTMLResponse(content='<div class="text-red-400 text-sm">Finding not found</div>')

    # Initialize model orchestrator to get analyzer
    orchestrator = ModelOrchestrator(db)
    await orchestrator.initialize()

    try:
        model_pool = orchestrator.get_primary_analyzer()
        if not model_pool:
            return HTMLResponse(content='<div class="text-red-400 text-sm">No analyzer model configured</div>')

        enricher = FindingEnricher(model_pool, db)
        fix = await enricher.generate_fix(
            title=finding.description,
            impacted_code=finding.snippet,
            vulnerability_details=finding.vulnerability_details or finding.description
        )

        # Save the fix to the finding
        finding.corrected_code = fix
        db.commit()

        # Return HTML partial for HTMX
        html = f'''
        <h4 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Corrected Code</h4>
        <div class="bg-green-950/30 rounded p-2 font-mono text-xs text-green-300 border border-green-900/50 mb-2">
            <pre class="whitespace-pre-wrap">{strip_code_blocks(fix)}</pre>
        </div>
        <button hx-post="/finding/{finding_id}/generate-fix"
                hx-target="#fix-container-{finding_id}"
                hx-swap="innerHTML"
                class="text-xs px-3 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition-colors">
            Regenerate Fix
        </button>
        '''
        return HTMLResponse(content=html)
    finally:
        await orchestrator.shutdown()


@router.get("/scan/{scan_id}/report/html")
async def download_html_report(scan_id: int, db: Session = Depends(get_db)):
    # TODO: Implement report generation
    return HTMLResponse(content="<h1>Report generation not yet implemented</h1>")


@router.get("/scan/{scan_id}/report/pdf")
async def download_pdf_report(scan_id: int, db: Session = Depends(get_db)):
    # TODO: Implement PDF report generation
    return {"error": "PDF generation not yet implemented"}


@router.get("/config", response_class=HTMLResponse)
async def get_config(request: Request):
    from app.core.config import settings
    return templates.TemplateResponse("config.html", {"request": request, "settings": settings})


@router.post("/config")
async def update_config(
    request: Request,
    llm_base_url: str = Form(...),
    llm_api_key: str = Form(...),
    llm_model: str = Form(...),
    llm_verification_models: str = Form(...),
    llm_verify_ssl: bool = Form(False)
):
    from app.core.config import settings
    settings.LLM_BASE_URL = llm_base_url
    settings.LLM_API_KEY = llm_api_key
    settings.LLM_MODEL = llm_model

    settings.LLM_VERIFICATION_MODELS = [m.strip() for m in llm_verification_models.split(",") if m.strip()]
    settings.LLM_VERIFY_SSL = llm_verify_ssl

    from app.services.llm_provider import llm_provider
    llm_provider.base_url = llm_base_url
    llm_provider.api_key = llm_api_key
    llm_provider.verify_ssl = llm_verify_ssl

    return templates.TemplateResponse("config.html", {"request": request, "settings": settings, "message": "Configuration saved!"})
