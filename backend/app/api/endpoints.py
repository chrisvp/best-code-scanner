from fastapi import APIRouter, Depends, Request, Form, BackgroundTasks, UploadFile, File
import os
import tempfile
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.database import get_db, engine, Base, SessionLocal
from app.models.models import Scan, Finding
from app.models.scanner_models import (
    ModelConfig, ScanConfig, ScanFile, ScanFileChunk,
    DraftFinding, VerifiedFinding, StaticRule, LLMCallMetric, ScanErrorLog,
    ScanProfile, ProfileAnalyzer, WebhookConfig, WebhookDeliveryLog
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
    archive: UploadFile = File(None),  # Optional file upload
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
    chunk_strategy: str = Form("smart"),  # lines, functions, or smart
    # File filtering options - scan specific files only
    file_filter: str = Form(None),  # Glob pattern: "*.c", "src/**/*.py", "sshd.c", "file1.c,file2.c"
    # Profile-based scanning
    profile_id: int = Form(None),  # Use a scan profile with custom analyzers
    db: Session = Depends(get_db)
):
    # Handle file upload if provided
    actual_target = target_url
    if archive and archive.filename:
        # Save uploaded file to sandbox directory
        sandbox_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sandbox")
        os.makedirs(sandbox_dir, exist_ok=True)
        file_path = os.path.join(sandbox_dir, archive.filename)
        with open(file_path, "wb") as f:
            content = await archive.read()
            f.write(content)
        actual_target = file_path

    # Create Scan Record
    new_scan = Scan(target_url=actual_target, status="queued")
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
        chunk_size=chunk_size,
        chunk_strategy=chunk_strategy,
        file_filter=file_filter,
        profile_id=profile_id
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


@router.get("/scan/{scan_id}/config")
async def get_scan_config(scan_id: int, db: Session = Depends(get_db)):
    """Get the configuration for a scan (for clone/rerun)"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    config = db.query(ScanConfig).filter(ScanConfig.scan_id == scan_id).first()
    if not config:
        return {"error": "Config not found"}

    return {
        "scan_id": scan_id,
        "target_url": scan.target_url,
        "status": scan.status,
        "created_at": str(scan.created_at),
        "config": {
            "analysis_mode": config.analysis_mode,
            "scope": config.scope,
            "multi_model_scan": config.multi_model_scan,
            "min_votes_to_verify": config.min_votes_to_verify,
            "deduplicate_drafts": config.deduplicate_drafts,
            "scanner_concurrency": config.scanner_concurrency,
            "verifier_concurrency": config.verifier_concurrency,
            "enricher_concurrency": config.enricher_concurrency,
            "batch_size": config.batch_size,
            "chunk_size": config.chunk_size,
            "chunk_strategy": config.chunk_strategy,
        }
    }


@router.post("/scan/{scan_id}/clone")
async def clone_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    # Allow overriding any config param
    target_url: str = Form(None),
    analysis_mode: str = Form(None),
    scope: str = Form(None),
    multi_model_scan: bool = Form(None),
    min_votes_to_verify: int = Form(None),
    deduplicate_drafts: bool = Form(None),
    scanner_concurrency: int = Form(None),
    verifier_concurrency: int = Form(None),
    enricher_concurrency: int = Form(None),
    batch_size: int = Form(None),
    chunk_size: int = Form(None),
    chunk_strategy: str = Form(None),
    file_filter: str = Form(None),  # Glob pattern: "*.c", "sshd.c", etc.
    auto_start: bool = Form(True),  # Start immediately by default
    db: Session = Depends(get_db)
):
    """Clone a scan with optional config overrides. Creates new scan from existing config."""
    # Get source scan and config
    source_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not source_scan:
        return {"error": "Source scan not found"}

    source_config = db.query(ScanConfig).filter(ScanConfig.scan_id == scan_id).first()
    if not source_config:
        return {"error": "Source config not found"}

    # Create new scan with source target (or override)
    new_scan = Scan(
        target_url=target_url if target_url else source_scan.target_url,
        status="queued" if auto_start else "draft"
    )
    db.add(new_scan)
    db.flush()

    # Clone config with optional overrides
    new_config = ScanConfig(
        scan_id=new_scan.id,
        analysis_mode=analysis_mode if analysis_mode else source_config.analysis_mode,
        scope=scope if scope else source_config.scope,
        multi_model_scan=multi_model_scan if multi_model_scan is not None else source_config.multi_model_scan,
        min_votes_to_verify=min_votes_to_verify if min_votes_to_verify is not None else source_config.min_votes_to_verify,
        deduplicate_drafts=deduplicate_drafts if deduplicate_drafts is not None else source_config.deduplicate_drafts,
        scanner_concurrency=scanner_concurrency if scanner_concurrency is not None else source_config.scanner_concurrency,
        verifier_concurrency=verifier_concurrency if verifier_concurrency is not None else source_config.verifier_concurrency,
        enricher_concurrency=enricher_concurrency if enricher_concurrency is not None else source_config.enricher_concurrency,
        batch_size=batch_size if batch_size is not None else source_config.batch_size,
        chunk_size=chunk_size if chunk_size is not None else source_config.chunk_size,
        chunk_strategy=chunk_strategy if chunk_strategy else source_config.chunk_strategy,
        file_filter=file_filter if file_filter else source_config.file_filter,
    )
    db.add(new_config)
    db.commit()

    # Start if requested
    if auto_start:
        background_tasks.add_task(run_pipeline, new_scan.id)

    return {
        "status": "cloned",
        "source_scan_id": scan_id,
        "new_scan_id": new_scan.id,
        "auto_started": auto_start
    }


@router.post("/scan/{scan_id}/rerun")
async def rerun_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    reset_all: bool = Form(True),  # Reset all findings/chunks or just pending
    db: Session = Depends(get_db)
):
    """Rerun a scan from scratch, keeping the same config."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    if scan.status == "running":
        return {"error": "Scan is already running"}

    if reset_all:
        # Delete all findings and chunks for this scan
        db.query(VerifiedFinding).filter(VerifiedFinding.scan_id == scan_id).delete()
        db.query(DraftFinding).filter(DraftFinding.scan_id == scan_id).delete()

        # Reset chunks to pending
        chunk_ids = db.query(ScanFileChunk.id).join(ScanFile).filter(
            ScanFile.scan_id == scan_id
        ).all()
        if chunk_ids:
            db.query(ScanFileChunk).filter(
                ScanFileChunk.id.in_([c[0] for c in chunk_ids])
            ).update({"status": "pending", "retry_count": 0}, synchronize_session=False)

        # Reset file status
        db.query(ScanFile).filter(ScanFile.scan_id == scan_id).update(
            {"status": "pending"}, synchronize_session=False
        )

    # Reset scan status and logs
    scan.status = "queued"
    scan.logs = f"[Rerun] Starting fresh scan at {scan.updated_at}\n"
    db.commit()

    # Start pipeline
    background_tasks.add_task(run_pipeline, scan_id)

    return {
        "status": "rerun_started",
        "scan_id": scan_id,
        "reset_all": reset_all
    }


@router.get("/scan/{scan_id}/progress")
async def get_progress(request: Request, scan_id: int, db: Session = Depends(get_db)):
    """Get detailed scan progress"""
    # Get scan status
    scan = db.query(Scan).filter(Scan.id == scan_id).first()

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

    # Error and retry stats
    failed_chunks = db.query(ScanFileChunk).join(ScanFile).filter(
        ScanFile.scan_id == scan_id,
        ScanFileChunk.status == "failed"
    ).count()

    retrying_chunks = db.query(ScanFileChunk).join(ScanFile).filter(
        ScanFile.scan_id == scan_id,
        ScanFileChunk.retry_count > 0,
        ScanFileChunk.status == "pending"
    ).count()

    total_errors = db.query(ScanErrorLog).filter(
        ScanErrorLog.scan_id == scan_id
    ).count()

    # Get error breakdown by type
    error_by_type = {}
    error_types = db.query(ScanErrorLog.error_type, func.count(ScanErrorLog.id)).filter(
        ScanErrorLog.scan_id == scan_id
    ).group_by(ScanErrorLog.error_type).all()
    for error_type, count in error_types:
        error_by_type[error_type or 'unknown'] = count

    progress = {
        "scan_id": scan_id,
        "scan": {
            "status": scan.status if scan else "unknown"
        },
        "chunks": {
            "total": total_chunks,
            "scanned": scanned_chunks,
            "failed": failed_chunks,
            "retrying": retrying_chunks,
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
        },
        "errors": {
            "total": total_errors,
            "by_type": error_by_type
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


@router.post("/scan/{scan_id}/stop")
async def stop_scan(scan_id: int, db: Session = Depends(get_db)):
    """Force stop a running or paused scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    if scan.status in ("running", "paused", "queued"):
        scan.status = "failed"
        scan.logs = (scan.logs or "") + "\n[STOPPED] Scan manually stopped by user"
        db.commit()
        return {"status": "stopped", "scan_id": scan_id}
    return {"error": "Scan is not running", "current_status": scan.status}


@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan and all associated data"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    # Don't allow deleting running scans
    if scan.status == "running":
        return {"error": "Cannot delete a running scan. Stop it first."}

    # Delete associated findings
    db.query(Finding).filter(Finding.scan_id == scan_id).delete()

    # Delete the scan
    db.delete(scan)
    db.commit()

    return {"status": "deleted", "scan_id": scan_id}


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
async def create_model(request: Request, db: Session = Depends(get_db)):
    """Create a new model configuration"""
    data = await request.json()

    # Check for duplicate name
    existing = db.query(ModelConfig).filter(ModelConfig.name == data.get('name')).first()
    if existing:
        return JSONResponse({"error": "Model with this name already exists"}, status_code=400)

    model = ModelConfig(
        name=data.get('name'),
        base_url=data.get('base_url'),
        api_key=data.get('api_key'),
        max_tokens=data.get('max_tokens', 4096),
        max_concurrent=data.get('max_concurrent', 2),
        votes=data.get('votes', 1),
        chunk_size=data.get('chunk_size', 3000),
        is_analyzer=data.get('is_analyzer', True),
        is_verifier=data.get('is_verifier', False)
    )
    db.add(model)
    db.commit()
    db.refresh(model)

    return {"status": "created", "id": model.id, "name": model.name}


@router.put("/models/{model_id}")
async def update_model(model_id: int, request: Request, db: Session = Depends(get_db)):
    """Update a model configuration"""
    model = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
    if not model:
        return JSONResponse({"error": "Model not found"}, status_code=404)

    data = await request.json()

    # Check for duplicate name (excluding current model)
    if data.get('name') and data['name'] != model.name:
        existing = db.query(ModelConfig).filter(ModelConfig.name == data['name']).first()
        if existing:
            return JSONResponse({"error": "Model with this name already exists"}, status_code=400)

    # Update fields
    if data.get('name'):
        model.name = data['name']
    if 'base_url' in data:
        model.base_url = data['base_url']
    if data.get('api_key'):
        model.api_key = data['api_key']
    if 'max_tokens' in data:
        model.max_tokens = data['max_tokens']
    if 'max_concurrent' in data:
        model.max_concurrent = data['max_concurrent']
    if 'votes' in data:
        model.votes = data['votes']
    if 'chunk_size' in data:
        model.chunk_size = data['chunk_size']
    if 'is_analyzer' in data:
        model.is_analyzer = data['is_analyzer']
    if 'is_verifier' in data:
        model.is_verifier = data['is_verifier']

    db.commit()
    return {"status": "updated", "id": model.id, "name": model.name}


@router.delete("/models/{model_id}")
async def delete_model(model_id: int, db: Session = Depends(get_db)):
    """Delete a model configuration"""
    model = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
    if not model:
        return JSONResponse({"error": "Model not found"}, status_code=404)

    db.delete(model)
    db.commit()
    return {"status": "deleted", "id": model_id}


@router.get("/models/performance")
async def model_performance(scan_id: int = None, db: Session = Depends(get_db)):
    """Get per-model performance metrics across scans.

    Returns detection rate (true positives), false positive rate, and timing stats.
    If scan_id provided, returns metrics for that scan only.
    """
    from collections import defaultdict
    import json

    # Query filters
    scan_filter = DraftFinding.scan_id == scan_id if scan_id else True
    metric_filter = LLMCallMetric.scan_id == scan_id if scan_id else True

    # Get all draft findings with their status and source models
    drafts = db.query(DraftFinding).filter(scan_filter).all()

    # Track per-model stats
    model_stats = defaultdict(lambda: {
        'detected': 0,       # Total findings reported by this model
        'verified': 0,       # Findings that were verified (true positives)
        'rejected': 0,       # Findings that were rejected (false positives)
        'pending': 0,        # Findings still pending verification
        'unique_finds': 0,   # Findings only this model found
    })

    # All models that participated in verified findings
    verified_models = set()

    for draft in drafts:
        source_models = draft.source_models or []

        # Handle legacy data that might be JSON string
        if isinstance(source_models, str):
            try:
                source_models = json.loads(source_models)
            except:
                source_models = []

        for model in source_models:
            model_stats[model]['detected'] += 1

            if draft.status == 'verified':
                model_stats[model]['verified'] += 1
                verified_models.add(model)
            elif draft.status == 'rejected':
                model_stats[model]['rejected'] += 1
            else:
                model_stats[model]['pending'] += 1

        # Track unique finds (only one model detected it)
        if len(source_models) == 1:
            model_stats[source_models[0]]['unique_finds'] += 1

    # Get timing stats from LLMCallMetric
    metrics = db.query(
        LLMCallMetric.model_name,
        LLMCallMetric.phase,
        func.sum(LLMCallMetric.call_count).label('calls'),
        func.sum(LLMCallMetric.total_time_ms).label('time_ms'),
        func.sum(LLMCallMetric.tokens_in).label('tokens_in'),
        func.sum(LLMCallMetric.tokens_out).label('tokens_out')
    ).filter(metric_filter).group_by(
        LLMCallMetric.model_name,
        LLMCallMetric.phase
    ).all()

    timing_stats = defaultdict(lambda: {'scanner': {}, 'verifier': {}, 'enricher': {}})
    for m in metrics:
        timing_stats[m.model_name][m.phase] = {
            'calls': m.calls or 0,
            'time_ms': round(m.time_ms or 0, 1),
            'tokens_in': m.tokens_in or 0,
            'tokens_out': m.tokens_out or 0
        }

    # Build response
    results = []
    for model, stats in model_stats.items():
        total = stats['detected']
        verified = stats['verified']
        rejected = stats['rejected']

        # Calculate rates
        precision = round(verified / (verified + rejected) * 100, 1) if (verified + rejected) > 0 else 0

        results.append({
            'model': model,
            'detected': total,
            'verified': verified,
            'rejected': rejected,
            'pending': stats['pending'],
            'unique_finds': stats['unique_finds'],
            'precision': precision,  # true positives / (true positives + false positives)
            'timing': timing_stats.get(model, {})
        })

    # Sort by precision (higher is better)
    results.sort(key=lambda x: (-x['precision'], -x['verified']))

    return {
        'scan_id': scan_id,
        'models': results,
        'summary': {
            'total_drafts': len(drafts),
            'verified': sum(1 for d in drafts if d.status == 'verified'),
            'rejected': sum(1 for d in drafts if d.status == 'rejected'),
            'pending': sum(1 for d in drafts if d.status not in ['verified', 'rejected'])
        }
    }


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
    base_url: str = Form(None),
    api_key: str = Form(None),
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

    if base_url is not None:
        model.base_url = base_url
    if api_key is not None:
        model.api_key = api_key
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


# Prompt Testing Endpoint
from pydantic import BaseModel
from typing import List

class PromptTestRequest(BaseModel):
    code: str
    models: List[str]
    prompt_template: str

@router.post("/test-prompt")
async def test_prompt(
    request: PromptTestRequest,
    db: Session = Depends(get_db)
):
    """Test a custom prompt against selected models"""
    from app.services.analysis.prompt_tester import PromptTesterService
    service = PromptTesterService(db)
    results = await service.test_prompt(request.code, request.models, request.prompt_template)
    return results


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


@router.post("/scan/{scan_id}/analyze-findings")
async def analyze_findings(scan_id: int, db: Session = Depends(get_db)):
    """
    Analyze all verified findings for a scan and provide prioritized recommendations.

    Returns:
        - summary: Brief overview of findings with severity counts
        - critical_priority: Findings needing immediate attention (with reason and CVSS)
        - quick_wins: Easy fixes with estimated effort
        - grouped: Findings grouped by root cause
        - remediation_order: Suggested order to fix findings
    """
    from app.services.analysis.findings_analyzer import FindingsAnalyzer
    from app.services.orchestration.model_orchestrator import ModelOrchestrator

    # Verify scan exists
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    # Check if scan has completed
    if scan.status not in ("completed", "failed"):
        return JSONResponse(
            {"error": f"Scan is still {scan.status}. Wait for completion before analyzing findings."},
            status_code=400
        )

    # Initialize model orchestrator to get analyzer
    orchestrator = ModelOrchestrator(db)
    await orchestrator.initialize()

    try:
        model_pool = orchestrator.get_primary_analyzer()
        if not model_pool:
            return JSONResponse(
                {"error": "No analyzer model configured. Add a model in /config first."},
                status_code=500
            )

        # Run analysis
        analyzer = FindingsAnalyzer(model_pool, db)
        result = await analyzer.analyze(scan_id)

        return result

    except Exception as e:
        import traceback
        print(f"Analysis error: {traceback.format_exc()}")
        return JSONResponse(
            {"error": f"Analysis failed: {str(e)}"},
            status_code=500
        )

    finally:
        await orchestrator.shutdown()


@router.get("/config", response_class=HTMLResponse)
async def get_config(request: Request, db: Session = Depends(get_db)):
    from app.core.config import settings
    from app.services.analysis.static_detector import StaticPatternDetector

    # Ensure defaults are seeded
    seed_default_profiles(db)
    StaticPatternDetector.seed_default_rules(db)

    models = db.query(ModelConfig).all()
    profiles = db.query(ScanProfile).order_by(ScanProfile.name).all()
    rules = db.query(StaticRule).order_by(StaticRule.severity, StaticRule.name).all()

    return templates.TemplateResponse("config.html", {
        "request": request,
        "settings": settings,
        "models": models,
        "profiles": profiles,
        "rules": rules
    })


@router.post("/config")
async def update_config(
    request: Request,
    db: Session = Depends(get_db),
    form_type: str = Form(None),
    llm_base_url: str = Form(None),
    llm_api_key: str = Form(None),
    llm_verify_ssl: bool = Form(False),
    max_concurrent: int = Form(None)
):
    from app.core.config import settings
    message = "Configuration saved!"

    if form_type == "connection":
        if llm_base_url:
            settings.LLM_BASE_URL = llm_base_url
        if llm_api_key:
            settings.LLM_API_KEY = llm_api_key
        settings.LLM_VERIFY_SSL = llm_verify_ssl

        from app.services.llm_provider import llm_provider
        if llm_base_url:
            llm_provider.base_url = llm_base_url
        if llm_api_key:
            llm_provider.api_key = llm_api_key
        llm_provider.verify_ssl = llm_verify_ssl
        message = "Connection settings saved!"

    elif form_type == "defaults":
        if max_concurrent:
            settings.MAX_CONCURRENT_REQUESTS = max_concurrent
        message = "Default settings saved!"

    models = db.query(ModelConfig).all()
    profiles = db.query(ScanProfile).order_by(ScanProfile.name).all()
    rules = db.query(StaticRule).order_by(StaticRule.severity, StaticRule.name).all()

    return templates.TemplateResponse("config.html", {
        "request": request,
        "settings": settings,
        "models": models,
        "profiles": profiles,
        "rules": rules,
        "message": message
    })


# ============== Static Rules Management ==============

@router.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request, db: Session = Depends(get_db)):
    """Static detection rules management page"""
    from app.services.analysis.static_detector import StaticPatternDetector

    # Ensure default rules are seeded
    StaticPatternDetector.seed_default_rules(db)

    rules = db.query(StaticRule).order_by(StaticRule.severity, StaticRule.name).all()
    return templates.TemplateResponse("rules.html", {"request": request, "rules": rules})


@router.get("/rules/list")
async def list_rules(db: Session = Depends(get_db)):
    """List all static detection rules (JSON API)"""
    rules = db.query(StaticRule).order_by(StaticRule.severity, StaticRule.name).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "pattern": r.pattern,
            "languages": r.languages,
            "cwe_id": r.cwe_id,
            "vulnerability_type": r.vulnerability_type,
            "severity": r.severity,
            "is_definite": r.is_definite,
            "enabled": r.enabled,
            "built_in": r.built_in,
            "match_count": r.match_count,
        }
        for r in rules
    ]


@router.post("/rules")
async def create_rule(
    request: Request,
    name: str = Form(...),
    pattern: str = Form(...),
    languages: str = Form(...),  # Comma-separated
    vulnerability_type: str = Form(...),
    severity: str = Form("High"),
    cwe_id: str = Form(None),
    description: str = Form(None),
    is_definite: bool = Form(True),
    db: Session = Depends(get_db)
):
    """Create a new static detection rule"""
    import re

    # Validate regex
    try:
        re.compile(pattern)
    except re.error as e:
        return {"error": f"Invalid regex pattern: {e}"}

    # Parse languages
    lang_list = [l.strip().lower() for l in languages.split(",") if l.strip()]

    rule = StaticRule(
        name=name,
        pattern=pattern,
        languages=lang_list,
        cwe_id=cwe_id if cwe_id else None,
        vulnerability_type=vulnerability_type,
        severity=severity,
        description=description,
        is_definite=is_definite,
        enabled=True,
        built_in=False,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    # Return updated rules list for HTMX
    if request.headers.get("HX-Request"):
        rules = db.query(StaticRule).order_by(StaticRule.severity, StaticRule.name).all()
        return templates.TemplateResponse("partials/rules_list.html", {"request": request, "rules": rules})

    return {"id": rule.id, "name": rule.name, "status": "created"}


@router.put("/rules/{rule_id}")
async def update_rule(
    rule_id: int,
    name: str = Form(None),
    pattern: str = Form(None),
    languages: str = Form(None),
    vulnerability_type: str = Form(None),
    severity: str = Form(None),
    cwe_id: str = Form(None),
    description: str = Form(None),
    is_definite: bool = Form(None),
    enabled: bool = Form(None),
    db: Session = Depends(get_db)
):
    """Update an existing rule"""
    import re

    rule = db.query(StaticRule).filter(StaticRule.id == rule_id).first()
    if not rule:
        return {"error": "Rule not found"}

    if pattern is not None:
        try:
            re.compile(pattern)
            rule.pattern = pattern
        except re.error as e:
            return {"error": f"Invalid regex pattern: {e}"}

    if name is not None:
        rule.name = name
    if languages is not None:
        rule.languages = [l.strip().lower() for l in languages.split(",") if l.strip()]
    if vulnerability_type is not None:
        rule.vulnerability_type = vulnerability_type
    if severity is not None:
        rule.severity = severity
    if cwe_id is not None:
        rule.cwe_id = cwe_id if cwe_id else None
    if description is not None:
        rule.description = description
    if is_definite is not None:
        rule.is_definite = is_definite
    if enabled is not None:
        rule.enabled = enabled

    db.commit()
    return {"id": rule.id, "name": rule.name, "status": "updated"}


@router.post("/rules/{rule_id}/toggle")
async def toggle_rule(request: Request, rule_id: int, db: Session = Depends(get_db)):
    """Toggle a rule's enabled status"""
    rule = db.query(StaticRule).filter(StaticRule.id == rule_id).first()
    if not rule:
        return {"error": "Rule not found"}

    rule.enabled = not rule.enabled
    db.commit()

    # Return updated row for HTMX
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/rule_row.html", {"request": request, "rule": rule})

    return {"id": rule.id, "enabled": rule.enabled}


@router.delete("/rules/{rule_id}")
async def delete_rule(request: Request, rule_id: int, db: Session = Depends(get_db)):
    """Delete a rule (only non-built-in rules)"""
    rule = db.query(StaticRule).filter(StaticRule.id == rule_id).first()
    if not rule:
        return {"error": "Rule not found"}

    if rule.built_in:
        return {"error": "Cannot delete built-in rules. Disable them instead."}

    db.delete(rule)
    db.commit()

    if request.headers.get("HX-Request"):
        return HTMLResponse(content="")  # Remove the row

    return {"status": "deleted", "id": rule_id}


@router.post("/rules/test")
async def test_rule(
    pattern: str = Form(...),
    test_code: str = Form(...),
):
    """Test a regex pattern against sample code"""
    import re

    try:
        compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        matches = []
        for match in compiled.finditer(test_code):
            line_num = test_code[:match.start()].count('\n') + 1
            matches.append({
                "line": line_num,
                "match": match.group(),
                "start": match.start(),
                "end": match.end(),
            })
        return {"valid": True, "matches": matches, "count": len(matches)}
    except re.error as e:
        return {"valid": False, "error": str(e)}


# ============== Interactive Chat ==============

# Store active chat sessions (in production use Redis or database)
_chat_sessions: dict = {}


@router.get("/scan/{scan_id}/chat", response_class=HTMLResponse)
async def chat_page(request: Request, scan_id: int, db: Session = Depends(get_db)):
    """Interactive chat page for a scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return HTMLResponse(content="<h1>Scan not found</h1>", status_code=404)

    return templates.TemplateResponse("chat.html", {
        "request": request,
        "scan": scan,
        "scan_id": scan_id
    })


@router.post("/scan/{scan_id}/chat/message")
async def chat_message(
    scan_id: int,
    message: str = Form(...),
    db: Session = Depends(get_db)
):
    """Send a message and get a response from the interactive agent"""
    from app.services.orchestration.model_orchestrator import ModelOrchestrator, ModelConfig, ModelPool

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    # Check if agent components are available
    try:
        from app.services.intelligence.codebase_tools import CodebaseTools
        from app.services.intelligence.agent_runtime import InteractiveAgent
    except ImportError:
        return {"error": "Interactive agent not available"}

    # Get or create chat session
    session_key = f"chat_{scan_id}"
    if session_key not in _chat_sessions:
        # Initialize model orchestrator to get primary analyzer
        orchestrator = ModelOrchestrator(db)
        await orchestrator.initialize()

        model_pool = orchestrator.get_primary_analyzer()
        if not model_pool:
            return {"error": "No analyzer model configured"}

        # Create codebase tools
        tools = CodebaseTools(
            scan_id=scan_id,
            root_dir=scan.target_path,
            db=db
        )

        # Create interactive agent
        agent = InteractiveAgent(model_pool, tools, max_steps=15)
        _chat_sessions[session_key] = {
            'agent': agent,
            'orchestrator': orchestrator
        }

    session = _chat_sessions[session_key]
    agent = session['agent']

    try:
        response = await agent.chat(message)
        return {
            "response": response,
            "status": "ok"
        }
    except Exception as e:
        return {
            "error": str(e),
            "status": "error"
        }


@router.post("/scan/{scan_id}/chat/reset")
async def reset_chat(scan_id: int):
    """Reset the chat session"""
    session_key = f"chat_{scan_id}"
    if session_key in _chat_sessions:
        session = _chat_sessions.pop(session_key)
        # Cleanup
        if 'orchestrator' in session:
            await session['orchestrator'].shutdown()

    return {"status": "ok", "message": "Chat session reset"}


@router.get("/scan/{scan_id}/chat/history")
async def chat_history(scan_id: int):
    """Get chat history for a session"""
    session_key = f"chat_{scan_id}"
    if session_key not in _chat_sessions:
        return {"messages": []}

    agent = _chat_sessions[session_key]['agent']
    return {"messages": agent.conversation_history}


# ============== General Chat (non-scan) ==============

@router.post("/chat/message")
async def general_chat_message(
    message: str = Form(...),
    db: Session = Depends(get_db)
):
    """General security chat endpoint (no specific scan context)"""
    from app.services.orchestration.model_orchestrator import ModelOrchestrator

    # Initialize model orchestrator
    orchestrator = ModelOrchestrator(db)
    await orchestrator.initialize()

    model_pool = orchestrator.get_primary_analyzer()
    if not model_pool:
        await orchestrator.shutdown()
        return {"error": "No analyzer model configured", "response": "Please configure an analyzer model in Settings."}

    try:
        # Simple single-turn chat without tools
        prompt = f"""You are a security expert assistant. Answer the following question about security best practices, vulnerability types, or general security topics.

Question: {message}

Provide a helpful, concise answer:"""

        response = await model_pool.call(prompt)
        await orchestrator.shutdown()

        return {
            "response": response,
            "status": "ok"
        }
    except Exception as e:
        await orchestrator.shutdown()
        return {
            "error": str(e),
            "response": f"Error: {str(e)}",
            "status": "error"
        }


# ============== Scan Profiles Management ==============

def seed_default_profiles(db: Session):
    """Seed default scan profiles if they don't exist"""
    from app.services.analysis.prompts import PROMPTS

    # Check if any profiles exist
    existing = db.query(ScanProfile).count()
    if existing > 0:
        return

    # Get default analyzer model
    default_model = db.query(ModelConfig).filter(ModelConfig.is_analyzer == True).first()

    # Profile 1: Quick Scan (single general pass)
    quick = ScanProfile(name="Quick Scan", description="Fast general security scan", chunk_size=4000, chunk_strategy="smart")
    db.add(quick)
    db.flush()
    db.add(ProfileAnalyzer(
        profile_id=quick.id, name="General Security", prompt_template=PROMPTS["general_security"],
        model_id=default_model.id if default_model else None, run_order=1
    ))

    # Profile 2: Deep C Audit (general + C-specific + signal handler)
    deep_c = ScanProfile(name="Deep C Audit", description="Comprehensive C/C++ security audit with signal safety checks", chunk_size=6000, chunk_strategy="smart")
    db.add(deep_c)
    db.flush()
    db.add(ProfileAnalyzer(
        profile_id=deep_c.id, name="General Security", prompt_template=PROMPTS["general_security"],
        model_id=default_model.id if default_model else None, file_filter="*.c,*.cpp,*.h,*.hpp", run_order=1
    ))
    db.add(ProfileAnalyzer(
        profile_id=deep_c.id, name="C Memory Safety", prompt_template=PROMPTS["c_memory_safety"],
        model_id=default_model.id if default_model else None, file_filter="*.c,*.cpp,*.h,*.hpp", run_order=2
    ))
    db.add(ProfileAnalyzer(
        profile_id=deep_c.id, name="Signal Handler Audit", prompt_template=PROMPTS["signal_handler"],
        model_id=default_model.id if default_model else None, file_filter="*.c,*.cpp,*.h,*.hpp", run_order=3
    ))

    # Profile 3: Python Audit
    python_audit = ScanProfile(name="Python Audit", description="Python-focused security analysis", chunk_size=6000, chunk_strategy="smart")
    db.add(python_audit)
    db.flush()
    db.add(ProfileAnalyzer(
        profile_id=python_audit.id, name="Python Security", prompt_template=PROMPTS["python_security"],
        model_id=default_model.id if default_model else None, file_filter="*.py", run_order=1
    ))

    # Profile 4: Crypto Audit
    crypto_audit = ScanProfile(name="Crypto Audit", description="Focus on cryptographic weaknesses", chunk_size=6000, chunk_strategy="smart")
    db.add(crypto_audit)
    db.flush()
    db.add(ProfileAnalyzer(
        profile_id=crypto_audit.id, name="Crypto Analysis", prompt_template=PROMPTS["crypto_audit"],
        model_id=default_model.id if default_model else None, run_order=1
    ))

    # Profile 5: CVE Hunt (race conditions + signal handlers - for catching CVE-2024-6387)
    cve_hunt = ScanProfile(name="CVE Hunt", description="Deep analysis for complex vulnerabilities like race conditions", chunk_size=8000, chunk_strategy="smart")
    db.add(cve_hunt)
    db.flush()
    db.add(ProfileAnalyzer(
        profile_id=cve_hunt.id, name="Race Condition Analysis", prompt_template=PROMPTS["race_condition"],
        model_id=default_model.id if default_model else None, run_order=1
    ))
    db.add(ProfileAnalyzer(
        profile_id=cve_hunt.id, name="Signal Handler Audit", prompt_template=PROMPTS["signal_handler"],
        model_id=default_model.id if default_model else None, file_filter="*.c,*.cpp,*.h,*.hpp", run_order=2
    ))

    db.commit()
    print("Seeded 5 default scan profiles")


@router.get("/profiles", response_class=HTMLResponse)
async def profiles_page(request: Request, db: Session = Depends(get_db)):
    """Scan profiles management page"""
    # Ensure default profiles exist
    seed_default_profiles(db)

    profiles = db.query(ScanProfile).order_by(ScanProfile.name).all()
    models = db.query(ModelConfig).all()
    return templates.TemplateResponse("profiles.html", {
        "request": request,
        "profiles": profiles,
        "models": models
    })


@router.get("/profiles/list")
async def list_profiles(db: Session = Depends(get_db)):
    """List all scan profiles (JSON API)"""
    seed_default_profiles(db)
    profiles = db.query(ScanProfile).order_by(ScanProfile.name).all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "chunk_size": p.chunk_size,
            "chunk_strategy": p.chunk_strategy,
            "enabled": p.enabled,
            "is_default": p.is_default,
            "analyzers": [
                {
                    "id": a.id,
                    "name": a.name,
                    "description": a.description,
                    "model_id": a.model_id,
                    "model_name": a.model.name if a.model else None,
                    "file_filter": a.file_filter,
                    "language_filter": a.language_filter,
                    "role": a.role,
                    "run_order": a.run_order,
                    "enabled": a.enabled,
                    "stop_on_findings": a.stop_on_findings,
                }
                for a in p.analyzers
            ]
        }
        for p in profiles
    ]


@router.get("/profiles/{profile_id}")
async def get_profile(profile_id: int, db: Session = Depends(get_db)):
    """Get a specific profile with its analyzers"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    return {
        "id": profile.id,
        "name": profile.name,
        "description": profile.description,
        "chunk_size": profile.chunk_size,
        "chunk_strategy": profile.chunk_strategy,
        "enabled": profile.enabled,
        "is_default": profile.is_default,
        "analyzers": [
            {
                "id": a.id,
                "name": a.name,
                "description": a.description,
                "model_id": a.model_id,
                "model_name": a.model.name if a.model else None,
                "prompt_template": a.prompt_template,
                "file_filter": a.file_filter,
                "language_filter": a.language_filter,
                "role": a.role,
                "run_order": a.run_order,
                "enabled": a.enabled,
                "stop_on_findings": a.stop_on_findings,
                "min_severity_to_report": a.min_severity_to_report,
            }
            for a in profile.analyzers
        ]
    }


@router.post("/profiles")
async def create_profile(
    name: str = Form(...),
    description: str = Form(None),
    chunk_size: int = Form(6000),
    chunk_strategy: str = Form("smart"),
    db: Session = Depends(get_db)
):
    """Create a new scan profile"""
    # Check for duplicate name
    existing = db.query(ScanProfile).filter(ScanProfile.name == name).first()
    if existing:
        return {"error": f"Profile '{name}' already exists"}

    profile = ScanProfile(
        name=name,
        description=description,
        chunk_size=chunk_size,
        chunk_strategy=chunk_strategy,
        enabled=True
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)

    return {"id": profile.id, "name": profile.name, "status": "created"}


@router.put("/profiles/{profile_id}")
async def update_profile(
    profile_id: int,
    name: str = Form(None),
    description: str = Form(None),
    chunk_size: int = Form(None),
    chunk_strategy: str = Form(None),
    enabled: bool = Form(None),
    is_default: bool = Form(None),
    db: Session = Depends(get_db)
):
    """Update a scan profile"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    if name is not None:
        profile.name = name
    if description is not None:
        profile.description = description
    if chunk_size is not None:
        profile.chunk_size = chunk_size
    if chunk_strategy is not None:
        profile.chunk_strategy = chunk_strategy
    if enabled is not None:
        profile.enabled = enabled
    if is_default is not None:
        # Clear other defaults if setting this one
        if is_default:
            db.query(ScanProfile).filter(ScanProfile.id != profile_id).update({"is_default": False})
        profile.is_default = is_default

    db.commit()
    return {"id": profile.id, "name": profile.name, "status": "updated"}


@router.delete("/profiles/{profile_id}")
async def delete_profile(profile_id: int, db: Session = Depends(get_db)):
    """Delete a scan profile and its analyzers"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    # Delete analyzers first
    db.query(ProfileAnalyzer).filter(ProfileAnalyzer.profile_id == profile_id).delete()
    db.delete(profile)
    db.commit()

    return {"status": "deleted", "id": profile_id}


@router.post("/profiles/{profile_id}/analyzers")
async def add_analyzer(
    profile_id: int,
    name: str = Form(...),
    prompt_template: str = Form(...),
    model_id: int = Form(None),
    description: str = Form(None),
    file_filter: str = Form(None),
    language_filter: str = Form(None),  # Comma-separated
    role: str = Form("analyzer"),
    run_order: int = Form(1),
    stop_on_findings: bool = Form(False),
    min_severity_to_report: str = Form(None),
    db: Session = Depends(get_db)
):
    """Add an analyzer to a profile"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    # Parse language filter
    lang_list = None
    if language_filter:
        lang_list = [l.strip().lower() for l in language_filter.split(",") if l.strip()]

    analyzer = ProfileAnalyzer(
        profile_id=profile_id,
        name=name,
        description=description,
        model_id=model_id,
        prompt_template=prompt_template,
        file_filter=file_filter,
        language_filter=lang_list,
        role=role,
        run_order=run_order,
        enabled=True,
        stop_on_findings=stop_on_findings,
        min_severity_to_report=min_severity_to_report
    )
    db.add(analyzer)
    db.commit()
    db.refresh(analyzer)

    return {"id": analyzer.id, "name": analyzer.name, "status": "created"}


@router.put("/profiles/{profile_id}/analyzers/{analyzer_id}")
async def update_analyzer(
    profile_id: int,
    analyzer_id: int,
    name: str = Form(None),
    prompt_template: str = Form(None),
    model_id: int = Form(None),
    description: str = Form(None),
    file_filter: str = Form(None),
    language_filter: str = Form(None),
    role: str = Form(None),
    run_order: int = Form(None),
    enabled: bool = Form(None),
    stop_on_findings: bool = Form(None),
    min_severity_to_report: str = Form(None),
    db: Session = Depends(get_db)
):
    """Update an analyzer"""
    analyzer = db.query(ProfileAnalyzer).filter(
        ProfileAnalyzer.id == analyzer_id,
        ProfileAnalyzer.profile_id == profile_id
    ).first()
    if not analyzer:
        return {"error": "Analyzer not found"}

    if name is not None:
        analyzer.name = name
    if prompt_template is not None:
        analyzer.prompt_template = prompt_template
    if model_id is not None:
        analyzer.model_id = model_id
    if description is not None:
        analyzer.description = description
    if file_filter is not None:
        analyzer.file_filter = file_filter if file_filter else None
    if language_filter is not None:
        if language_filter:
            analyzer.language_filter = [l.strip().lower() for l in language_filter.split(",") if l.strip()]
        else:
            analyzer.language_filter = None
    if role is not None:
        analyzer.role = role
    if run_order is not None:
        analyzer.run_order = run_order
    if enabled is not None:
        analyzer.enabled = enabled
    if stop_on_findings is not None:
        analyzer.stop_on_findings = stop_on_findings
    if min_severity_to_report is not None:
        analyzer.min_severity_to_report = min_severity_to_report if min_severity_to_report else None

    db.commit()
    return {"id": analyzer.id, "name": analyzer.name, "status": "updated"}


@router.delete("/profiles/{profile_id}/analyzers/{analyzer_id}")
async def delete_analyzer(profile_id: int, analyzer_id: int, db: Session = Depends(get_db)):
    """Delete an analyzer from a profile"""
    analyzer = db.query(ProfileAnalyzer).filter(
        ProfileAnalyzer.id == analyzer_id,
        ProfileAnalyzer.profile_id == profile_id
    ).first()
    if not analyzer:
        return {"error": "Analyzer not found"}

    db.delete(analyzer)
    db.commit()

    return {"status": "deleted", "id": analyzer_id}


@router.post("/profiles/{profile_id}/analyzers/{analyzer_id}/toggle")
async def toggle_analyzer(profile_id: int, analyzer_id: int, db: Session = Depends(get_db)):
    """Toggle an analyzer's enabled status"""
    analyzer = db.query(ProfileAnalyzer).filter(
        ProfileAnalyzer.id == analyzer_id,
        ProfileAnalyzer.profile_id == profile_id
    ).first()
    if not analyzer:
        return {"error": "Analyzer not found"}

    analyzer.enabled = not analyzer.enabled
    db.commit()

    return {"id": analyzer.id, "enabled": analyzer.enabled}


# ============== Webhook Security Alerts ==============

@router.get("/webhooks")
async def list_webhooks(db: Session = Depends(get_db)):
    """List all webhook configurations"""
    webhooks = db.query(WebhookConfig).order_by(WebhookConfig.created_at.desc()).all()
    return [
        {
            "id": w.id,
            "name": w.name,
            "url": w.url,
            "events": w.events or [],
            "min_severity": w.min_severity,
            "enabled": w.enabled,
            "last_triggered": w.last_triggered.isoformat() if w.last_triggered else None,
            "trigger_count": w.trigger_count or 0,
            "last_error": w.last_error,
            "created_at": w.created_at.isoformat() if w.created_at else None,
        }
        for w in webhooks
    ]


@router.post("/webhooks")
async def create_webhook(
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    secret: str = Form(None),
    events: str = Form(...),  # Comma-separated: malicious_intent,critical_finding,scan_complete
    min_severity: str = Form("High"),
    db: Session = Depends(get_db)
):
    """Create a new webhook configuration"""
    # Parse events
    event_list = [e.strip() for e in events.split(",") if e.strip()]

    # Validate events
    valid_events = {"malicious_intent", "critical_finding", "scan_complete"}
    invalid = set(event_list) - valid_events
    if invalid:
        return JSONResponse(
            {"error": f"Invalid events: {invalid}. Valid events: {valid_events}"},
            status_code=400
        )

    # Validate URL
    if not url.startswith(("http://", "https://")):
        return JSONResponse(
            {"error": "URL must start with http:// or https://"},
            status_code=400
        )

    webhook = WebhookConfig(
        name=name,
        url=url,
        secret=secret if secret else None,
        events=event_list,
        min_severity=min_severity,
        enabled=True
    )
    db.add(webhook)
    db.commit()
    db.refresh(webhook)

    return {"id": webhook.id, "name": webhook.name, "status": "created"}


@router.put("/webhooks/{webhook_id}")
async def update_webhook(
    webhook_id: int,
    name: str = Form(None),
    url: str = Form(None),
    secret: str = Form(None),
    events: str = Form(None),
    min_severity: str = Form(None),
    enabled: bool = Form(None),
    db: Session = Depends(get_db)
):
    """Update a webhook configuration"""
    webhook = db.query(WebhookConfig).filter(WebhookConfig.id == webhook_id).first()
    if not webhook:
        return JSONResponse({"error": "Webhook not found"}, status_code=404)

    if name is not None:
        webhook.name = name
    if url is not None:
        if not url.startswith(("http://", "https://")):
            return JSONResponse(
                {"error": "URL must start with http:// or https://"},
                status_code=400
            )
        webhook.url = url
    if secret is not None:
        webhook.secret = secret if secret else None
    if events is not None:
        event_list = [e.strip() for e in events.split(",") if e.strip()]
        valid_events = {"malicious_intent", "critical_finding", "scan_complete"}
        invalid = set(event_list) - valid_events
        if invalid:
            return JSONResponse(
                {"error": f"Invalid events: {invalid}. Valid events: {valid_events}"},
                status_code=400
            )
        webhook.events = event_list
    if min_severity is not None:
        webhook.min_severity = min_severity
    if enabled is not None:
        webhook.enabled = enabled

    db.commit()
    return {"id": webhook.id, "name": webhook.name, "status": "updated"}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: int, db: Session = Depends(get_db)):
    """Delete a webhook configuration and its delivery logs"""
    webhook = db.query(WebhookConfig).filter(WebhookConfig.id == webhook_id).first()
    if not webhook:
        return JSONResponse({"error": "Webhook not found"}, status_code=404)

    # Delete delivery logs first
    db.query(WebhookDeliveryLog).filter(WebhookDeliveryLog.webhook_id == webhook_id).delete()
    db.delete(webhook)
    db.commit()

    return {"status": "deleted", "id": webhook_id}


@router.post("/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id: int, db: Session = Depends(get_db)):
    """Send a test webhook to verify configuration"""
    from app.services.webhook_service import WebhookService

    webhook = db.query(WebhookConfig).filter(WebhookConfig.id == webhook_id).first()
    if not webhook:
        return JSONResponse({"error": "Webhook not found"}, status_code=404)

    service = WebhookService(db)
    try:
        result = await service.send_test_webhook(webhook_id)
        return result
    finally:
        await service.close()


@router.post("/webhooks/{webhook_id}/toggle")
async def toggle_webhook(webhook_id: int, db: Session = Depends(get_db)):
    """Toggle a webhook's enabled status"""
    webhook = db.query(WebhookConfig).filter(WebhookConfig.id == webhook_id).first()
    if not webhook:
        return JSONResponse({"error": "Webhook not found"}, status_code=404)

    webhook.enabled = not webhook.enabled
    db.commit()

    return {"id": webhook.id, "enabled": webhook.enabled}


@router.get("/webhooks/logs")
async def get_webhook_logs(
    webhook_id: int = None,
    scan_id: int = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Get recent webhook delivery logs"""
    from app.services.webhook_service import WebhookService

    service = WebhookService(db)
    deliveries = service.get_recent_deliveries(
        limit=limit,
        webhook_id=webhook_id,
        scan_id=scan_id
    )

    return {"deliveries": deliveries, "count": len(deliveries)}


@router.post("/webhooks/analyze-finding")
async def analyze_finding_malicious_intent(request: Request, db: Session = Depends(get_db)):
    """
    Analyze a finding for malicious intent indicators without sending webhooks.
    Useful for testing or previewing what would trigger alerts.
    """
    from app.services.webhook_service import analyze_malicious_intent

    data = await request.json()

    finding = {
        "title": data.get("title", ""),
        "snippet": data.get("snippet", ""),
        "reason": data.get("reason", ""),
        "vulnerability_type": data.get("vulnerability_type", ""),
        "description": data.get("description", ""),
    }

    result = analyze_malicious_intent(finding)
    return result


@router.post("/finding/{finding_id}/send-alert")
async def send_finding_alert(finding_id: int, db: Session = Depends(get_db)):
    """
    Manually trigger a webhook alert for a specific finding.
    Useful for testing or re-sending alerts.
    """
    from app.services.webhook_service import WebhookService

    # Try to find the finding in draft or verified findings
    draft = db.query(DraftFinding).filter(DraftFinding.id == finding_id).first()

    if draft:
        # Get file path from chunk
        chunk = db.query(ScanFileChunk).filter(ScanFileChunk.id == draft.chunk_id).first()
        scan_file = db.query(ScanFile).filter(ScanFile.id == chunk.scan_file_id).first() if chunk else None

        finding_data = {
            "id": draft.id,
            "title": draft.title,
            "file_path": scan_file.file_path if scan_file else "unknown",
            "line_number": draft.line_number,
            "snippet": draft.snippet,
            "severity": draft.severity,
            "vulnerability_type": draft.vulnerability_type,
            "reason": draft.reason,
            "initial_votes": draft.initial_votes,
        }
        scan_id = draft.scan_id
    else:
        # Try verified findings
        verified = db.query(VerifiedFinding).filter(VerifiedFinding.id == finding_id).first()
        if not verified:
            return JSONResponse({"error": "Finding not found"}, status_code=404)

        # Get draft for additional details
        draft = db.query(DraftFinding).filter(DraftFinding.id == verified.draft_id).first()
        chunk = db.query(ScanFileChunk).filter(ScanFileChunk.id == draft.chunk_id).first() if draft else None
        scan_file = db.query(ScanFile).filter(ScanFile.id == chunk.scan_file_id).first() if chunk else None

        finding_data = {
            "id": verified.id,
            "title": verified.title,
            "file_path": scan_file.file_path if scan_file else "unknown",
            "line_number": draft.line_number if draft else 0,
            "snippet": draft.snippet if draft else "",
            "severity": verified.adjusted_severity or (draft.severity if draft else "Medium"),
            "vulnerability_type": draft.vulnerability_type if draft else "",
            "confidence": verified.confidence,
            "attack_vector": verified.attack_vector,
        }
        scan_id = verified.scan_id

    service = WebhookService(db)
    try:
        result = await service.send_alert(finding_data, scan_id)
        return result
    finally:
        await service.close()


@router.post("/scan/{scan_id}/send-completion-alert")
async def send_scan_completion_alert(scan_id: int, db: Session = Depends(get_db)):
    """
    Manually trigger a scan completion webhook alert.
    Useful for testing or re-sending alerts.
    """
    from app.services.webhook_service import WebhookService

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    # Build summary
    total_findings = db.query(VerifiedFinding).filter(
        VerifiedFinding.scan_id == scan_id,
        VerifiedFinding.status == "complete"
    ).count()

    findings_by_severity = {}
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = db.query(VerifiedFinding).filter(
            VerifiedFinding.scan_id == scan_id,
            VerifiedFinding.status == "complete",
            VerifiedFinding.adjusted_severity.ilike(severity)
        ).count()
        findings_by_severity[severity.lower()] = count

    files_scanned = db.query(ScanFile).filter(ScanFile.scan_id == scan_id).count()

    # Count malicious intent findings
    from app.services.webhook_service import analyze_malicious_intent
    malicious_count = 0
    drafts = db.query(DraftFinding).filter(
        DraftFinding.scan_id == scan_id,
        DraftFinding.status == "verified"
    ).all()
    for draft in drafts:
        result = analyze_malicious_intent({
            "title": draft.title,
            "snippet": draft.snippet,
            "reason": draft.reason,
            "vulnerability_type": draft.vulnerability_type,
        })
        if result["is_malicious"]:
            malicious_count += 1

    summary = {
        "total_findings": total_findings,
        "critical": findings_by_severity.get("critical", 0),
        "high": findings_by_severity.get("high", 0),
        "medium": findings_by_severity.get("medium", 0),
        "low": findings_by_severity.get("low", 0),
        "malicious_intent_count": malicious_count,
        "files_scanned": files_scanned,
        "duration_seconds": 0,  # Would need scan timing data
    }

    service = WebhookService(db)
    try:
        result = await service.send_scan_complete(scan_id, summary)
        return result
    finally:
        await service.close()
