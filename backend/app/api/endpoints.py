from fastapi import APIRouter, Depends, Request, Form, BackgroundTasks, UploadFile, File
from typing import Optional
import os
import tempfile
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.database import get_db, engine, Base, SessionLocal
from app.models.models import Scan, Finding, GeneratedFix
from app.models.scanner_models import (
    ModelConfig, ScanConfig, ScanFile, ScanFileChunk,
    DraftFinding, VerifiedFinding, StaticRule, LLMCallMetric, ScanErrorLog,
    ScanProfile, ProfileAnalyzer, WebhookConfig, WebhookDeliveryLog,
    RepoWatcher, MRReview
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

    # Get MR reviews with their findings
    mr_reviews = db.query(MRReview).order_by(MRReview.created_at.desc()).all()
    for review in mr_reviews:
        review.findings = db.query(Finding).filter(Finding.mr_review_id == review.id).all()

    # Get all findings from both sources
    all_findings = db.query(Finding).order_by(Finding.id.desc()).all()

    # Get scan profiles for the dropdown
    profiles = db.query(ScanProfile).filter(ScanProfile.enabled == True).order_by(ScanProfile.name).all()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "scans": scans,
        "mr_reviews": mr_reviews,
        "all_findings": all_findings,
        "profiles": profiles
    })


@router.post("/scan/start")
async def start_scan(
    background_tasks: BackgroundTasks,
    target_url: str = Form(""),  # Optional if archive is provided
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
    # Validate: either target_url or archive must be provided
    has_archive = archive and archive.filename
    has_url = target_url and target_url.strip()
    if not has_archive and not has_url:
        raise HTTPException(status_code=400, detail="Either a Git URL or an archive file must be provided")

    # Handle file upload if provided
    actual_target = target_url
    if has_archive:
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


# ============ Finding Details & Chat ============

@router.get("/finding/{finding_id}", response_class=HTMLResponse)
async def get_finding_details(request: Request, finding_id: int, db: Session = Depends(get_db)):
    """Get the finding details page with AI chat"""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return HTMLResponse(content="<h1>Finding not found</h1>", status_code=404)

    # Get available models for the fix generator
    models = db.query(ModelConfig).order_by(ModelConfig.name).all()

    # Get scan info if available
    scan = None
    if finding.scan_id:
        scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()

    # Get MR review info if available
    mr_review = None
    if finding.mr_review_id:
        mr_review = db.query(MRReview).filter(MRReview.id == finding.mr_review_id).first()

    return templates.TemplateResponse("finding_details.html", {
        "request": request,
        "finding": finding,
        "models": models,
        "scan": scan,
        "mr_review": mr_review
    })


@router.delete("/finding/{finding_id}")
async def delete_finding(finding_id: int, db: Session = Depends(get_db)):
    """Delete a finding"""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return JSONResponse({"error": "Finding not found"}, status_code=404)

    db.delete(finding)
    db.commit()
    return JSONResponse({"success": True, "message": "Finding deleted"})


@router.post("/finding/{finding_id}/chat")
async def finding_chat(finding_id: int, request: Request, db: Session = Depends(get_db)):
    """Chat about a specific finding with AI context"""
    from app.services.llm_provider import LLMProvider
    from app.core.config import settings

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return JSONResponse({"error": "Finding not found"}, status_code=404)

    try:
        data = await request.json()
        user_message = data.get("message", "")
        history = data.get("history", [])
        model_id = data.get("model_id")

        if not user_message:
            return JSONResponse({"error": "No message provided"}, status_code=400)

        # Build context about the finding
        context = f"""You are a security expert assistant helping analyze a vulnerability finding.

## Finding Context
- **File**: {finding.file_path}
- **Line**: {finding.line_number or 'N/A'}
- **Severity**: {finding.severity}
- **Category**: {finding.category or 'N/A'}
- **Description**: {finding.description}

"""
        if finding.snippet:
            context += f"""## Vulnerable Code
```
{finding.snippet}
```

"""
        if finding.remediation:
            context += f"""## Current Remediation Suggestion
{finding.remediation}

"""
        if finding.vulnerability_details:
            context += f"""## Additional Details
{finding.vulnerability_details}

"""

        context += """## Your Role
Help the user understand this vulnerability, explain attack vectors, suggest fixes,
generate tests, or provide alternative remediation strategies. Be specific and provide
code examples when relevant. Format responses with markdown for code blocks."""

        # Build messages for the LLM
        messages = [{"role": "system", "content": context}]

        # Add chat history (limited)
        for msg in history[-8:]:
            messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})

        # Add current message
        messages.append({"role": "user", "content": user_message})

        # Get model config - use specified model_id, or prefer model with is_chat role, fall back to any model
        model_config = None
        if model_id:
            model_config = db.query(ModelConfig).filter(ModelConfig.id == int(model_id)).first()

        if not model_config:
            model_config = db.query(ModelConfig).filter(ModelConfig.is_chat == True).first()

        if not model_config:
            # Fall back to any configured model
            model_config = db.query(ModelConfig).first()

        # Use the model name if we have a config, otherwise use default
        model_name = model_config.name if model_config else None

        # Call LLM using the global provider
        from app.services.llm_provider import llm_provider
        result = await llm_provider.chat_completion(
            messages=messages,
            model=model_name,
            max_tokens=2000
        )

        return {"response": result.get("content", "")}

    except Exception as e:
        import traceback
        print(f"Chat error: {traceback.format_exc()}")
        return JSONResponse({"error": str(e)}, status_code=500)


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
            "is_verifier": m.is_verifier,
            "is_cleanup": m.is_cleanup,
            "is_chat": m.is_chat
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
        is_verifier=data.get('is_verifier', False),
        is_cleanup=data.get('is_cleanup', False),
        is_chat=data.get('is_chat', False)
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
    if 'is_cleanup' in data:
        model.is_cleanup = data['is_cleanup']
    if 'is_chat' in data:
        model.is_chat = data['is_chat']

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


@router.get("/finding/{finding_id}/code-context")
async def get_code_context(finding_id: int, context_lines: int = 10, db: Session = Depends(get_db)):
    """Get code context around the vulnerable line with line numbers"""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return {"error": "Finding not found"}

    file_path = finding.file_path
    line_number = finding.line_number or 1

    # Try to find the actual file
    possible_paths = [
        file_path,
        os.path.join("/mnt/c/Users/acrvp/code/code-scanner/backend", file_path),
        os.path.join("/mnt/c/Users/acrvp/code/code-scanner/backend/sandbox", file_path),
    ]

    actual_path = None
    for p in possible_paths:
        if os.path.exists(p):
            actual_path = p
            break

    if not actual_path:
        # Return just the snippet if file not found
        return {
            "lines": [{"number": line_number, "content": finding.snippet or "", "is_vulnerable": True}],
            "file_found": False
        }

    try:
        with open(actual_path, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines = f.readlines()

        total_lines = len(all_lines)
        start = max(0, line_number - context_lines - 1)
        end = min(total_lines, line_number + context_lines)

        lines = []
        for i in range(start, end):
            lines.append({
                "number": i + 1,
                "content": all_lines[i].rstrip('\n\r'),
                "is_vulnerable": i + 1 == line_number
            })

        return {
            "lines": lines,
            "file_found": True,
            "vulnerable_line": line_number
        }
    except Exception as e:
        return {"error": str(e), "file_found": False}


@router.get("/finding/{finding_id}/fixes")
async def list_fixes(finding_id: int, db: Session = Depends(get_db)):
    """List all generated fixes for a finding"""
    fixes = db.query(GeneratedFix).filter(GeneratedFix.finding_id == finding_id).order_by(GeneratedFix.created_at.desc()).all()
    return {
        "fixes": [
            {
                "id": f.id,
                "fix_type": f.fix_type,
                "model_name": f.model_name,
                "code": f.code,
                "reasoning": f.reasoning,
                "created_at": f.created_at.isoformat() if f.created_at else None
            }
            for f in fixes
        ],
        "count": len(fixes)
    }


@router.post("/finding/{finding_id}/generate-fix")
async def generate_fix(finding_id: int, request: Request, db: Session = Depends(get_db)):
    """Generate a quick fix with full file context (single-shot LLM call)"""
    import json
    from app.services.fix_generator import FixGenerator

    # Parse JSON body for model_id
    model_id = None
    try:
        body = await request.json()
        model_id = body.get("model_id")
    except:
        pass

    # Get the finding
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return {"error": "Finding not found"}

    # Get model name if specified
    model_name = None
    if model_id:
        model_config = db.query(ModelConfig).filter(ModelConfig.id == int(model_id)).first()
        if model_config:
            model_name = model_config.name

    try:
        generator = FixGenerator(db)
        fix = await generator.quick_fix(finding, model=model_name)

        # Save to GeneratedFix table
        generated_fix = GeneratedFix(
            finding_id=finding_id,
            fix_type="quick",
            model_name=model_name,
            code=fix
        )
        db.add(generated_fix)

        # Also update finding's corrected_code
        finding.corrected_code = fix
        db.commit()

        # Get total count of fixes
        fix_count = db.query(GeneratedFix).filter(GeneratedFix.finding_id == finding_id).count()

        return {
            "corrected_code": fix,
            "fix_id": generated_fix.id,
            "fix_index": 0,
            "fix_count": fix_count
        }
    except Exception as e:
        import traceback
        print(f"Quick fix error: {traceback.format_exc()}")
        return {"error": str(e)}


@router.post("/finding/{finding_id}/agent-fix")
async def agent_fix(finding_id: int, request: Request, db: Session = Depends(get_db)):
    """Generate a fix using agentic approach with tool use (multi-turn, more accurate)"""
    import json
    from app.services.fix_generator import FixGenerator

    # Parse JSON body for model_id
    model_id = None
    try:
        body = await request.json()
        model_id = body.get("model_id")
    except:
        pass

    # Get the finding
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return {"error": "Finding not found"}

    # Get model name if specified
    model_name = None
    if model_id:
        model_config = db.query(ModelConfig).filter(ModelConfig.id == int(model_id)).first()
        if model_config:
            model_name = model_config.name

    try:
        generator = FixGenerator(db)
        result = await generator.agent_fix(finding, model=model_name)

        fix = result.get("fix", "")
        reasoning = result.get("reasoning", [])

        # Save to GeneratedFix table
        if fix:
            generated_fix = GeneratedFix(
                finding_id=finding_id,
                fix_type="agent",
                model_name=model_name,
                code=fix,
                reasoning=json.dumps(reasoning) if reasoning else None
            )
            db.add(generated_fix)

            # Also update finding's corrected_code
            finding.corrected_code = fix
            db.commit()

            # Get total count of fixes
            fix_count = db.query(GeneratedFix).filter(GeneratedFix.finding_id == finding_id).count()

            return {
                "corrected_code": fix,
                "reasoning": reasoning,
                "iterations": result.get("iterations", 0),
                "fix_id": generated_fix.id,
                "fix_index": 0,
                "fix_count": fix_count
            }

        return {
            "corrected_code": fix,
            "reasoning": reasoning,
            "iterations": result.get("iterations", 0)
        }
    except Exception as e:
        import traceback
        print(f"Agent fix error: {traceback.format_exc()}")
        return {"error": str(e)}


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
    from app.models.scanner_models import GitLabRepo

    # Ensure defaults are seeded
    seed_default_profiles(db)
    StaticPatternDetector.seed_default_rules(db)

    models = db.query(ModelConfig).all()
    profiles = db.query(ScanProfile).order_by(ScanProfile.name).all()
    rules = db.query(StaticRule).order_by(StaticRule.severity, StaticRule.name).all()
    gitlab_repos = db.query(GitLabRepo).order_by(GitLabRepo.name).all()

    return templates.TemplateResponse("config.html", {
        "request": request,
        "settings": settings,
        "models": models,
        "profiles": profiles,
        "rules": rules,
        "gitlab_repos": gitlab_repos
    })


@router.post("/config")
async def update_config(
    request: Request,
    db: Session = Depends(get_db),
    form_type: str = Form(None),
    llm_base_url: str = Form(None),
    llm_api_key: str = Form(None),
    llm_verify_ssl: bool = Form(False),
    max_concurrent: int = Form(None),
    scanner_url_prefix: str = Form(None)
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
        if scanner_url_prefix is not None:
            # Strip trailing slash if present
            settings.SCANNER_URL_PREFIX = scanner_url_prefix.rstrip('/')
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
    model_id: Optional[int] = Form(None),
    db: Session = Depends(get_db)
):
    """Send a message and get a response from the interactive agent"""
    from app.services.orchestration.model_orchestrator import ModelOrchestrator, ModelConfig as ModelConfigClass, ModelPool

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    # Check if agent components are available
    try:
        from app.services.intelligence.codebase_tools import CodebaseTools
        from app.services.intelligence.agent_runtime import InteractiveAgent
    except ImportError:
        return {"error": "Interactive agent not available"}

    # Get or create chat session (include model_id in key for different model sessions)
    session_key = f"chat_{scan_id}_{model_id or 'default'}"
    if session_key not in _chat_sessions:
        # Initialize model orchestrator
        orchestrator = ModelOrchestrator(db)
        await orchestrator.initialize()

        # Get specific model or primary analyzer
        model_pool = None
        if model_id:
            model_config = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
            if model_config:
                model_pool = orchestrator.get_pool(model_config.name)

        if not model_pool:
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
    model_id: Optional[int] = Form(None),
    db: Session = Depends(get_db)
):
    """General security chat endpoint (no specific scan context)"""
    from app.services.orchestration.model_orchestrator import ModelOrchestrator

    # Initialize model orchestrator
    orchestrator = ModelOrchestrator(db)
    await orchestrator.initialize()

    # Get specific model, or chat model, or primary analyzer
    model_pool = None
    if model_id:
        model_config = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
        if model_config:
            model_pool = orchestrator.get_pool(model_config.name)

    if not model_pool:
        # Try to get the configured chat model first
        chat_model = db.query(ModelConfig).filter(ModelConfig.is_chat == True).first()
        if chat_model:
            model_pool = orchestrator.get_pool(chat_model.name)

    if not model_pool:
        # Fallback to primary analyzer
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

    # Get default analyzer model - required for creating profiles
    default_model = db.query(ModelConfig).filter(ModelConfig.is_analyzer == True).first()
    if not default_model:
        # Can't create profiles without at least one analyzer model
        print("Skipping profile seeding - no analyzer models configured yet")
        return

    # Profile 1: Quick Scan (single general pass)
    quick = ScanProfile(name="Quick Scan", description="Fast general security scan", chunk_size=4000, chunk_strategy="smart")
    db.add(quick)
    db.flush()
    db.add(ProfileAnalyzer(
        profile_id=quick.id, name="General Security", prompt_template=PROMPTS["general_security"],
        model_id=default_model.id, run_order=1
    ))

    # Profile 2: Deep C Audit (general + C-specific + signal handler)
    deep_c = ScanProfile(name="Deep C Audit", description="Comprehensive C/C++ security audit with signal safety checks", chunk_size=6000, chunk_strategy="smart")
    db.add(deep_c)
    db.flush()
    db.add(ProfileAnalyzer(
        profile_id=deep_c.id, name="General Security", prompt_template=PROMPTS["general_security"],
        model_id=default_model.id, file_filter="*.c,*.cpp,*.h,*.hpp", run_order=1
    ))
    db.add(ProfileAnalyzer(
        profile_id=deep_c.id, name="C Memory Safety", prompt_template=PROMPTS["c_memory_safety"],
        model_id=default_model.id, file_filter="*.c,*.cpp,*.h,*.hpp", run_order=2
    ))
    db.add(ProfileAnalyzer(
        profile_id=deep_c.id, name="Signal Handler Audit", prompt_template=PROMPTS["signal_handler"],
        model_id=default_model.id, file_filter="*.c,*.cpp,*.h,*.hpp", run_order=3
    ))

    # Profile 3: Python Audit
    python_audit = ScanProfile(name="Python Audit", description="Python-focused security analysis", chunk_size=6000, chunk_strategy="smart")
    db.add(python_audit)
    db.flush()
    db.add(ProfileAnalyzer(
        profile_id=python_audit.id, name="Python Security", prompt_template=PROMPTS["python_security"],
        model_id=default_model.id, file_filter="*.py", run_order=1
    ))

    # Profile 4: Crypto Audit
    crypto_audit = ScanProfile(name="Crypto Audit", description="Focus on cryptographic weaknesses", chunk_size=6000, chunk_strategy="smart")
    db.add(crypto_audit)
    db.flush()
    db.add(ProfileAnalyzer(
        profile_id=crypto_audit.id, name="Crypto Analysis", prompt_template=PROMPTS["crypto_audit"],
        model_id=default_model.id, run_order=1
    ))

    # Profile 5: CVE Hunt (race conditions + signal handlers - for catching CVE-2024-6387)
    cve_hunt = ScanProfile(name="CVE Hunt", description="Deep analysis for complex vulnerabilities like race conditions", chunk_size=8000, chunk_strategy="smart")
    db.add(cve_hunt)
    db.flush()
    db.add(ProfileAnalyzer(
        profile_id=cve_hunt.id, name="Race Condition Analysis", prompt_template=PROMPTS["race_condition"],
        model_id=default_model.id, run_order=1
    ))
    db.add(ProfileAnalyzer(
        profile_id=cve_hunt.id, name="Signal Handler Audit", prompt_template=PROMPTS["signal_handler"],
        model_id=default_model.id, file_filter="*.c,*.cpp,*.h,*.hpp", run_order=2
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
                "chunk_size": a.chunk_size,
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
    model_id: int = Form(...),
    chunk_size: int = Form(6000),
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
        chunk_size=chunk_size,
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
    chunk_size: int = Form(None),
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
    if chunk_size is not None:
        analyzer.chunk_size = chunk_size
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


# ============== Manual MR Review ==============

@router.get("/mr-review", response_class=HTMLResponse)
async def mr_review_page(request: Request, db: Session = Depends(get_db)):
    """Manual MR review page"""
    from app.models.scanner_models import GitLabRepo
    profiles = db.query(ScanProfile).filter(ScanProfile.enabled == True).order_by(ScanProfile.name).all()
    gitlab_repos = db.query(GitLabRepo).order_by(GitLabRepo.name).all()
    return templates.TemplateResponse("mr_review.html", {
        "request": request,
        "profiles": profiles,
        "gitlab_repos": gitlab_repos
    })


@router.post("/mr-review/analyze")
async def analyze_mr(
    gitlab_repo_id: int = Form(None),
    gitlab_url: str = Form(None),
    gitlab_token: str = Form(None),
    project_id: str = Form(None),
    mr_iid: int = Form(...),
    scan_profile_id: int = Form(None),
    post_comments: bool = Form(False),
    db: Session = Depends(get_db)
):
    """
    Analyze a specific MR for security vulnerabilities.
    Returns generated comments without requiring a watcher.
    Can use a saved GitLab repo or manual credentials.
    Logs all reviews to mr_reviews table and findings to findings table.
    """
    from app.services.gitlab_service import GitLabService, GitLabError
    from app.services.mr_reviewer_service import MRReviewerService
    from app.models.scanner_models import GitLabRepo, MRReview
    from app.models.models import Finding
    from datetime import datetime, timezone
    import json

    try:
        # Get credentials from saved repo or manual entry
        if gitlab_repo_id:
            repo = db.query(GitLabRepo).filter(GitLabRepo.id == gitlab_repo_id).first()
            if not repo:
                return JSONResponse({"error": "Saved repo not found"}, status_code=404)
            use_url = repo.gitlab_url
            use_token = repo.gitlab_token
            use_project = repo.project_id
            use_verify_ssl = repo.verify_ssl if repo.verify_ssl is not None else False
        else:
            if not gitlab_token or not project_id:
                return JSONResponse({"error": "Either select a saved repo or provide GitLab token and project ID"}, status_code=400)
            use_url = gitlab_url or "https://192.168.33.158"
            use_token = gitlab_token
            use_project = project_id
            use_verify_ssl = False

        # Create GitLab client
        gitlab = GitLabService(
            gitlab_url=use_url.rstrip('/'),
            token=use_token,
            verify_ssl=use_verify_ssl
        )

        # Get MR details
        mr_details = await gitlab.get_merge_request(use_project, mr_iid)
        diff_data = await gitlab.get_mr_diff(use_project, mr_iid)

        # Create MR Review record in database
        mr_review = MRReview(
            gitlab_repo_id=gitlab_repo_id,  # Will be None for manual entry
            mr_iid=mr_iid,
            mr_title=mr_details.get("title"),
            mr_url=mr_details.get("web_url"),
            mr_author=mr_details.get("author", {}).get("username"),
            source_branch=mr_details.get("source_branch"),
            target_branch=mr_details.get("target_branch"),
            status="reviewing",
            post_comments=post_comments,
        )
        db.add(mr_review)
        db.flush()  # Get the ID

        # Create a temporary reviewer service instance
        reviewer = MRReviewerService(db)

        # Analyze the diff
        changes = diff_data.get("changes", [])
        all_findings = []
        files_reviewed = 0

        for change in changes:
            file_path = change.get("new_path", "")

            if not reviewer._is_scannable_file(file_path):
                continue

            diff_content = change.get("diff", "")
            if not diff_content:
                continue

            files_reviewed += 1

            # Analyze with LLM
            findings = await reviewer._analyze_diff_with_llm(file_path, diff_content)

            for finding in findings:
                finding["file_path"] = file_path
                all_findings.append(finding)

        # Generate summary
        summary = await reviewer._generate_summary(files_reviewed, all_findings)

        # Generate comments (always, regardless of post_comments)
        generated_comments = {
            "inline_comments": [],
            "summary_comment": None
        }

        base_sha = diff_data.get("diff_refs", {}).get("base_sha")
        head_sha = diff_data.get("diff_refs", {}).get("head_sha")
        start_sha = diff_data.get("diff_refs", {}).get("start_sha")

        for finding in all_findings:
            comment_body = reviewer._format_inline_comment(finding)
            generated_comments["inline_comments"].append({
                "file_path": finding["file_path"],
                "line": finding.get("line", 1),
                "body": comment_body,
            })

        summary_comment = reviewer._format_summary_comment(
            files_reviewed=files_reviewed,
            findings=all_findings,
            summary=summary,
        )
        generated_comments["summary_comment"] = summary_comment

        # Post to GitLab if requested
        comments_posted = []
        if post_comments and all_findings:
            for gen_comment in generated_comments["inline_comments"]:
                try:
                    result = await gitlab.post_inline_comment(
                        project_id=use_project,
                        mr_iid=mr_iid,
                        file_path=gen_comment["file_path"],
                        new_line=gen_comment["line"],
                        comment=gen_comment["body"],
                        base_sha=base_sha,
                        head_sha=head_sha,
                        start_sha=start_sha,
                    )
                    comments_posted.append(result.get("id"))
                except GitLabError as e:
                    pass  # Continue with other comments

            # Post summary
            try:
                result = await gitlab.post_mr_comment(
                    project_id=use_project,
                    mr_iid=mr_iid,
                    comment=generated_comments["summary_comment"],
                )
                comments_posted.append(result.get("id"))
            except GitLabError:
                pass

        await gitlab.close()

        # Store findings in the unified findings table
        for finding_data in all_findings:
            finding = Finding(
                mr_review_id=mr_review.id,
                file_path=finding_data.get("file_path", ""),
                line_number=finding_data.get("line", 1),
                severity=finding_data.get("severity", "MEDIUM"),
                description=finding_data.get("description", ""),
                snippet=finding_data.get("snippet", ""),
                remediation=finding_data.get("recommendation", ""),
                category=finding_data.get("type", ""),  # CWE type
            )
            db.add(finding)

        # Update MR Review record with results
        mr_review.files_reviewed = files_reviewed
        mr_review.diff_findings = json.dumps(all_findings)
        mr_review.diff_summary = summary
        mr_review.diff_reviewed_at = datetime.now(timezone.utc)
        mr_review.generated_comments = json.dumps(generated_comments)
        mr_review.comments_posted = json.dumps(comments_posted)
        mr_review.status = "completed"
        mr_review.approval_status = reviewer._determine_approval_status(all_findings)

        db.commit()

        return {
            "mr_iid": mr_iid,
            "mr_review_id": mr_review.id,
            "mr_title": mr_details.get("title"),
            "mr_url": mr_details.get("web_url"),
            "source_branch": mr_details.get("source_branch"),
            "target_branch": mr_details.get("target_branch"),
            "files_reviewed": files_reviewed,
            "finding_count": len(all_findings),
            "findings": all_findings,
            "summary": summary,
            "inline_comments": generated_comments["inline_comments"],
            "summary_comment": generated_comments["summary_comment"],
            "comments_generated": len(generated_comments["inline_comments"]) + (1 if generated_comments["summary_comment"] else 0),
            "comments_posted": len(comments_posted),
            "post_comments": post_comments,
        }

    except GitLabError as e:
        return JSONResponse({"error": f"GitLab API error: {str(e)}"}, status_code=400)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({"error": str(e)}, status_code=500)


# ============== MR Reviews List ==============

@router.get("/mr-reviews", response_class=HTMLResponse)
async def mr_reviews_list_page(request: Request, db: Session = Depends(get_db)):
    """List all MR reviews with their findings from database"""
    # Get all MR reviews - findings are loaded via relationship
    reviews = db.query(MRReview).order_by(MRReview.created_at.desc()).all()

    return templates.TemplateResponse("mr_reviews.html", {
        "request": request,
        "reviews": reviews
    })


@router.get("/mr-reviews/{review_id}/details", response_class=HTMLResponse)
async def mr_review_details(request: Request, review_id: int, db: Session = Depends(get_db)):
    """Get detailed view of a specific MR review including findings"""
    from app.models.models import Finding
    import json

    review = db.query(MRReview).filter(MRReview.id == review_id).first()
    if not review:
        return HTMLResponse("<div class='text-red-400 p-4'>Review not found</div>", status_code=404)

    # Get findings from database
    findings = db.query(Finding).filter(Finding.mr_review_id == review_id).all()

    # Parse stored JSON data if available
    generated_comments = []
    summary_comment = None
    if review.generated_comments:
        try:
            comments_data = json.loads(review.generated_comments) if isinstance(review.generated_comments, str) else review.generated_comments
            generated_comments = comments_data.get("inline_comments", [])
            summary_comment = comments_data.get("summary_comment")
        except:
            pass

    return templates.TemplateResponse("partials/mr_review_details.html", {
        "request": request,
        "review": review,
        "findings": findings,
        "generated_comments": generated_comments,
        "summary_comment": summary_comment
    })


@router.post("/mr-reviews/{review_id}/rerun")
async def rerun_mr_review(review_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Re-run an MR review (temporary endpoint for testing)"""
    from app.models.models import Finding
    from app.services.mr_reviewer_service import MRReviewerService

    review = db.query(MRReview).filter(MRReview.id == review_id).first()
    if not review:
        return {"success": False, "error": "Review not found"}

    watcher = db.query(RepoWatcher).filter(RepoWatcher.id == review.watcher_id).first()
    if not watcher:
        return {"success": False, "error": "Watcher not found"}

    # Delete existing findings for this review
    db.query(Finding).filter(Finding.mr_review_id == review_id).delete()

    # Reset review status
    review.status = "pending"
    review.diff_summary = None
    review.generated_comments = None
    review.files_reviewed = 0
    review.comments_posted = False
    review.diff_reviewed_at = None
    db.commit()

    async def run_review():
        service = MRReviewerService(db)
        # Build MR info from the review record
        # Include both iid (GitLab) and number (GitHub) for compatibility
        mr_info = {
            "iid": review.mr_iid,
            "number": review.mr_iid,  # GitHub uses "number" for PR number
            "title": review.mr_title,
            "source_branch": review.source_branch,
            "target_branch": review.target_branch,
            "author": {"username": review.mr_author} if review.mr_author else None,
            "web_url": review.mr_url,
            "head": {"sha": None},  # GitHub PR structure
            "base": {"ref": review.target_branch},  # GitHub PR structure
        }
        await service.review_mr_diff(watcher, mr_info)

    background_tasks.add_task(run_review)

    return {"success": True, "message": "Review re-run started"}


# ============== Saved GitLab Repos ==============

@router.get("/gitlab-repos")
async def list_gitlab_repos(db: Session = Depends(get_db)):
    """List all saved GitLab repos"""
    from app.models.scanner_models import GitLabRepo
    repos = db.query(GitLabRepo).order_by(GitLabRepo.name).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "gitlab_url": r.gitlab_url,
            "project_id": r.project_id,
            "description": r.description,
            "verify_ssl": r.verify_ssl,
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in repos
    ]


@router.post("/gitlab-repos")
async def create_gitlab_repo(
    name: str = Form(...),
    gitlab_url: str = Form("https://192.168.33.158"),
    gitlab_token: str = Form(...),
    project_id: str = Form(...),
    description: str = Form(None),
    verify_ssl: bool = Form(False),
    db: Session = Depends(get_db)
):
    """Create a new saved GitLab repo"""
    from app.models.scanner_models import GitLabRepo

    repo = GitLabRepo(
        name=name,
        gitlab_url=gitlab_url.rstrip('/'),
        gitlab_token=gitlab_token,
        project_id=project_id,
        description=description,
        verify_ssl=verify_ssl
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)

    return {
        "id": repo.id,
        "name": repo.name,
        "gitlab_url": repo.gitlab_url,
        "project_id": repo.project_id,
        "description": repo.description,
        "verify_ssl": repo.verify_ssl
    }


@router.put("/gitlab-repos/{repo_id}")
async def update_gitlab_repo(
    repo_id: int,
    name: str = Form(None),
    gitlab_url: str = Form(None),
    gitlab_token: str = Form(None),
    project_id: str = Form(None),
    description: str = Form(None),
    verify_ssl: bool = Form(None),
    db: Session = Depends(get_db)
):
    """Update a saved GitLab repo"""
    from app.models.scanner_models import GitLabRepo

    repo = db.query(GitLabRepo).filter(GitLabRepo.id == repo_id).first()
    if not repo:
        return JSONResponse({"error": "Repo not found"}, status_code=404)

    if name:
        repo.name = name
    if gitlab_url:
        repo.gitlab_url = gitlab_url.rstrip('/')
    if gitlab_token:
        repo.gitlab_token = gitlab_token
    if project_id:
        repo.project_id = project_id
    if description is not None:
        repo.description = description
    if verify_ssl is not None:
        repo.verify_ssl = verify_ssl

    db.commit()
    return {"status": "ok"}


@router.delete("/gitlab-repos/{repo_id}")
async def delete_gitlab_repo(repo_id: int, db: Session = Depends(get_db)):
    """Delete a saved GitLab repo"""
    from app.models.scanner_models import GitLabRepo

    repo = db.query(GitLabRepo).filter(GitLabRepo.id == repo_id).first()
    if not repo:
        return JSONResponse({"error": "Repo not found"}, status_code=404)

    db.delete(repo)
    db.commit()
    return {"status": "ok"}


@router.get("/gitlab-repos/{repo_id}")
async def get_gitlab_repo(repo_id: int, db: Session = Depends(get_db)):
    """Get a single GitLab repo by ID"""
    from app.models.scanner_models import GitLabRepo

    repo = db.query(GitLabRepo).filter(GitLabRepo.id == repo_id).first()
    if not repo:
        return JSONResponse({"error": "Repo not found"}, status_code=404)

    return {
        "id": repo.id,
        "name": repo.name,
        "gitlab_url": repo.gitlab_url,
        "gitlab_token": repo.gitlab_token,  # Include for form population
        "project_id": repo.project_id,
        "description": repo.description,
        "verify_ssl": repo.verify_ssl
    }


# ============== Saved GitHub Repos ==============

@router.get("/github-repos")
async def list_github_repos(db: Session = Depends(get_db)):
    """List all saved GitHub repos"""
    from app.models.scanner_models import GitHubRepo
    repos = db.query(GitHubRepo).order_by(GitHubRepo.name).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "github_url": r.github_url,
            "owner": r.owner,
            "repo": r.repo,
            "description": r.description,
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in repos
    ]


@router.post("/github-repos")
async def create_github_repo(
    name: str = Form(...),
    github_url: str = Form("https://api.github.com"),
    github_token: str = Form(...),
    owner: str = Form(...),
    repo: str = Form(...),
    description: str = Form(None),
    db: Session = Depends(get_db)
):
    """Create a new saved GitHub repo"""
    from app.models.scanner_models import GitHubRepo

    github_repo = GitHubRepo(
        name=name,
        github_url=github_url.rstrip('/'),
        github_token=github_token,
        owner=owner,
        repo=repo,
        description=description
    )
    db.add(github_repo)
    db.commit()
    db.refresh(github_repo)

    return {
        "id": github_repo.id,
        "name": github_repo.name,
        "github_url": github_repo.github_url,
        "owner": github_repo.owner,
        "repo": github_repo.repo,
        "description": github_repo.description
    }


@router.put("/github-repos/{repo_id}")
async def update_github_repo(
    repo_id: int,
    name: str = Form(None),
    github_url: str = Form(None),
    github_token: str = Form(None),
    owner: str = Form(None),
    repo: str = Form(None),
    description: str = Form(None),
    db: Session = Depends(get_db)
):
    """Update a saved GitHub repo"""
    from app.models.scanner_models import GitHubRepo

    github_repo = db.query(GitHubRepo).filter(GitHubRepo.id == repo_id).first()
    if not github_repo:
        return JSONResponse({"error": "GitHub repo not found"}, status_code=404)

    if name:
        github_repo.name = name
    if github_url:
        github_repo.github_url = github_url.rstrip('/')
    if github_token:
        github_repo.github_token = github_token
    if owner:
        github_repo.owner = owner
    if repo:
        github_repo.repo = repo
    if description is not None:
        github_repo.description = description

    db.commit()
    return {"status": "ok"}


@router.delete("/github-repos/{repo_id}")
async def delete_github_repo(repo_id: int, db: Session = Depends(get_db)):
    """Delete a saved GitHub repo"""
    from app.models.scanner_models import GitHubRepo

    github_repo = db.query(GitHubRepo).filter(GitHubRepo.id == repo_id).first()
    if not github_repo:
        return JSONResponse({"error": "GitHub repo not found"}, status_code=404)

    db.delete(github_repo)
    db.commit()
    return {"status": "ok"}


@router.get("/github-repos/{repo_id}")
async def get_github_repo(repo_id: int, db: Session = Depends(get_db)):
    """Get a single GitHub repo by ID"""
    from app.models.scanner_models import GitHubRepo

    github_repo = db.query(GitHubRepo).filter(GitHubRepo.id == repo_id).first()
    if not github_repo:
        return JSONResponse({"error": "GitHub repo not found"}, status_code=404)

    return {
        "id": github_repo.id,
        "name": github_repo.name,
        "github_url": github_repo.github_url,
        "github_token": github_repo.github_token,  # Include for form population
        "owner": github_repo.owner,
        "repo": github_repo.repo,
        "description": github_repo.description
    }


# ============== Repository Watchers ==============

@router.get("/watchers/page", response_class=HTMLResponse)
async def watchers_page(request: Request, db: Session = Depends(get_db)):
    """Repo watchers management page"""
    from app.models.scanner_models import GitLabRepo, GitHubRepo
    watchers = db.query(RepoWatcher).order_by(RepoWatcher.created_at.desc()).all()
    profiles = db.query(ScanProfile).filter(ScanProfile.enabled == True).order_by(ScanProfile.name).all()
    gitlab_repos = db.query(GitLabRepo).order_by(GitLabRepo.name).all()
    github_repos = db.query(GitHubRepo).order_by(GitHubRepo.name).all()
    return templates.TemplateResponse("watchers.html", {
        "request": request,
        "watchers": watchers,
        "profiles": profiles,
        "gitlab_repos": gitlab_repos,
        "github_repos": github_repos
    })


@router.get("/watchers")
async def list_watchers(db: Session = Depends(get_db)):
    """List all repo watchers (JSON API)"""
    watchers = db.query(RepoWatcher).order_by(RepoWatcher.created_at.desc()).all()
    return [
        {
            "id": w.id,
            "name": w.name,
            "provider": w.provider or "gitlab",
            "gitlab_url": w.gitlab_url,
            "project_id": w.project_id,
            "github_url": w.github_url,
            "github_owner": w.github_owner,
            "github_repo_name": w.github_repo_name,
            "branch_filter": w.branch_filter,
            "label_filter": w.label_filter,
            "scan_profile_id": w.scan_profile_id,
            "scan_profile_name": w.scan_profile.name if w.scan_profile else None,
            "review_model_id": w.review_model_id,
            "review_model_name": w.review_model.name if w.review_model else None,
            "poll_interval": w.poll_interval,
            "status": w.status,
            "last_check": w.last_check.isoformat() if w.last_check else None,
            "last_error": w.last_error,
            "review_count": len(w.reviews) if w.reviews else 0,
            "enabled": w.enabled,
            "post_comments": w.post_comments,
            "created_at": w.created_at.isoformat() if w.created_at else None,
        }
        for w in watchers
    ]


@router.post("/watchers")
async def create_watcher(
    request: Request,
    name: str = Form(...),
    provider: str = Form("gitlab"),
    # GitLab fields
    gitlab_url: str = Form("https://gitlab.com"),
    gitlab_token: str = Form(None),
    project_id: str = Form(None),
    gitlab_repo_id: int = Form(None),
    # GitHub fields
    github_url: str = Form("https://api.github.com"),
    github_token: str = Form(None),
    github_owner: str = Form(None),
    github_repo_name: str = Form(None),
    github_repo_id: int = Form(None),
    # Common fields
    branch_filter: str = Form(None),
    label_filter: str = Form(None),
    scan_profile_id: int = Form(None),
    review_model_id: int = Form(None),
    poll_interval: int = Form(300),
    max_files_to_review: int = Form(100),
    mr_lookback_days: int = Form(7),
    post_comments: bool = Form(False),
    db: Session = Depends(get_db)
):
    """Create a new repo watcher (supports GitLab and GitHub)"""
    from app.models.scanner_models import GitLabRepo, GitHubRepo

    # Check for duplicate name
    existing = db.query(RepoWatcher).filter(RepoWatcher.name == name).first()
    if existing:
        return JSONResponse({"error": f"Watcher '{name}' already exists"}, status_code=400)

    # Create base watcher
    watcher = RepoWatcher(
        name=name,
        provider=provider,
        branch_filter=branch_filter if branch_filter else None,
        label_filter=label_filter if label_filter else None,
        scan_profile_id=scan_profile_id if scan_profile_id else None,
        review_model_id=review_model_id if review_model_id else None,
        poll_interval=max(60, poll_interval),
        max_files_to_review=max(1, min(1000, max_files_to_review)),
        mr_lookback_days=max(0, min(365, mr_lookback_days)),
        post_comments=post_comments,
        status="paused",
        enabled=True
    )

    if provider == "github":
        # Handle GitHub watcher
        # Set default values for GitLab fields to satisfy NOT NULL constraints
        watcher.gitlab_url = ""
        watcher.project_id = ""

        if github_repo_id:
            # Using saved GitHub repo
            saved_repo = db.query(GitHubRepo).filter(GitHubRepo.id == github_repo_id).first()
            if not saved_repo:
                return JSONResponse({"error": "Saved GitHub repository not found"}, status_code=400)
            watcher.github_repo_id = github_repo_id
        else:
            # Manual entry
            if not github_owner or not github_repo_name:
                return JSONResponse({"error": "GitHub owner and repo are required"}, status_code=400)
            watcher.github_url = github_url.rstrip('/') if github_url else "https://api.github.com"
            watcher.github_token = github_token
            watcher.github_owner = github_owner
            watcher.github_repo_name = github_repo_name
    else:
        # Handle GitLab watcher (default)
        if gitlab_repo_id:
            # Using saved GitLab repo
            saved_repo = db.query(GitLabRepo).filter(GitLabRepo.id == gitlab_repo_id).first()
            if not saved_repo:
                return JSONResponse({"error": "Saved GitLab repository not found"}, status_code=400)
            watcher.gitlab_repo_id = gitlab_repo_id
        else:
            # Manual entry
            if not gitlab_url.startswith(("http://", "https://")):
                return JSONResponse({"error": "GitLab URL must start with http:// or https://"}, status_code=400)
            if not project_id:
                return JSONResponse({"error": "GitLab project ID is required"}, status_code=400)
            watcher.gitlab_url = gitlab_url.rstrip('/')
            watcher.gitlab_token = gitlab_token
            watcher.project_id = project_id

    db.add(watcher)
    db.commit()
    db.refresh(watcher)

    # Return updated list for HTMX
    if request.headers.get("HX-Request"):
        watchers = db.query(RepoWatcher).order_by(RepoWatcher.created_at.desc()).all()
        profiles = db.query(ScanProfile).filter(ScanProfile.enabled == True).order_by(ScanProfile.name).all()
        return templates.TemplateResponse("partials/watcher_list.html", {
            "request": request,
            "watchers": watchers,
            "profiles": profiles
        })

    return {"id": watcher.id, "name": watcher.name, "status": "created"}


@router.get("/watchers/{watcher_id}")
async def get_watcher(watcher_id: int, db: Session = Depends(get_db)):
    """Get a specific watcher with details"""
    watcher = db.query(RepoWatcher).filter(RepoWatcher.id == watcher_id).first()
    if not watcher:
        return JSONResponse({"error": "Watcher not found"}, status_code=404)

    return {
        "id": watcher.id,
        "name": watcher.name,
        "gitlab_url": watcher.gitlab_url,
        "project_id": watcher.project_id,
        "branch_filter": watcher.branch_filter,
        "label_filter": watcher.label_filter,
        "scan_profile_id": watcher.scan_profile_id,
        "scan_profile_name": watcher.scan_profile.name if watcher.scan_profile else None,
        "review_model_id": watcher.review_model_id,
        "review_model_name": watcher.review_model.name if watcher.review_model else None,
        "poll_interval": watcher.poll_interval,
        "status": watcher.status,
        "last_check": watcher.last_check.isoformat() if watcher.last_check else None,
        "last_error": watcher.last_error,
        "review_count": len(watcher.reviews) if watcher.reviews else 0,
        "enabled": watcher.enabled,
        "post_comments": watcher.post_comments,
        "created_at": watcher.created_at.isoformat() if watcher.created_at else None,
    }


@router.put("/watchers/{watcher_id}")
async def update_watcher(
    watcher_id: int,
    name: str = Form(None),
    gitlab_url: str = Form(None),
    gitlab_token: str = Form(None),
    project_id: str = Form(None),
    branch_filter: str = Form(None),
    label_filter: str = Form(None),
    scan_profile_id: int = Form(None),
    review_model_id: int = Form(None),
    poll_interval: int = Form(None),
    max_files_to_review: int = Form(None),
    mr_lookback_days: int = Form(None),
    enabled: bool = Form(None),
    post_comments: bool = Form(None),
    db: Session = Depends(get_db)
):
    """Update a repo watcher"""
    watcher = db.query(RepoWatcher).filter(RepoWatcher.id == watcher_id).first()
    if not watcher:
        return JSONResponse({"error": "Watcher not found"}, status_code=404)

    if name is not None:
        # Check for duplicate name
        existing = db.query(RepoWatcher).filter(
            RepoWatcher.name == name,
            RepoWatcher.id != watcher_id
        ).first()
        if existing:
            return JSONResponse({"error": f"Watcher '{name}' already exists"}, status_code=400)
        watcher.name = name

    if gitlab_url is not None:
        if not gitlab_url.startswith(("http://", "https://")):
            return JSONResponse({"error": "GitLab URL must start with http:// or https://"}, status_code=400)
        watcher.gitlab_url = gitlab_url.rstrip('/')

    if gitlab_token is not None:
        watcher.gitlab_token = gitlab_token

    if project_id is not None:
        watcher.project_id = project_id

    if branch_filter is not None:
        watcher.branch_filter = branch_filter if branch_filter else None

    if label_filter is not None:
        watcher.label_filter = label_filter if label_filter else None

    if scan_profile_id is not None:
        watcher.scan_profile_id = scan_profile_id if scan_profile_id else None

    if review_model_id is not None:
        watcher.review_model_id = review_model_id if review_model_id else None

    if poll_interval is not None:
        watcher.poll_interval = max(60, poll_interval)

    if max_files_to_review is not None:
        watcher.max_files_to_review = max(1, min(1000, max_files_to_review))

    if mr_lookback_days is not None:
        watcher.mr_lookback_days = max(0, min(365, mr_lookback_days))

    if enabled is not None:
        watcher.enabled = enabled

    if post_comments is not None:
        watcher.post_comments = post_comments

    db.commit()
    return {"id": watcher.id, "name": watcher.name, "status": "updated"}


@router.delete("/watchers/{watcher_id}")
async def delete_watcher(request: Request, watcher_id: int, db: Session = Depends(get_db)):
    """Delete a repo watcher and its reviews"""
    watcher = db.query(RepoWatcher).filter(RepoWatcher.id == watcher_id).first()
    if not watcher:
        return JSONResponse({"error": "Watcher not found"}, status_code=404)

    # Don't allow deleting running watchers
    if watcher.status == "running":
        return JSONResponse({"error": "Stop the watcher before deleting"}, status_code=400)

    # Delete reviews first
    db.query(MRReview).filter(MRReview.watcher_id == watcher_id).delete()
    db.delete(watcher)
    db.commit()

    if request.headers.get("HX-Request"):
        return HTMLResponse(content="")  # Remove the row

    return {"status": "deleted", "id": watcher_id}


@router.post("/watchers/{watcher_id}/start")
async def start_watcher(request: Request, watcher_id: int, db: Session = Depends(get_db)):
    """Start watching for new MRs"""
    watcher = db.query(RepoWatcher).filter(RepoWatcher.id == watcher_id).first()
    if not watcher:
        return JSONResponse({"error": "Watcher not found"}, status_code=404)

    if not watcher.enabled:
        return JSONResponse({"error": "Watcher is disabled"}, status_code=400)

    watcher.status = "running"
    watcher.last_error = None
    db.commit()

    # Return updated row for HTMX
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/watcher_row.html", {
            "request": request,
            "watcher": watcher
        })

    return {"id": watcher.id, "status": "running"}


@router.post("/watchers/{watcher_id}/stop")
async def stop_watcher(request: Request, watcher_id: int, db: Session = Depends(get_db)):
    """Stop watching for new MRs"""
    watcher = db.query(RepoWatcher).filter(RepoWatcher.id == watcher_id).first()
    if not watcher:
        return JSONResponse({"error": "Watcher not found"}, status_code=404)

    watcher.status = "paused"
    db.commit()

    # Return updated row for HTMX
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/watcher_row.html", {
            "request": request,
            "watcher": watcher
        })

    return {"id": watcher.id, "status": "paused"}


@router.post("/watchers/{watcher_id}/poll")
async def poll_watcher_now(
    watcher_id: int,
    db: Session = Depends(get_db)
):
    """Force poll for new MRs/PRs now"""
    from app.services.mr_reviewer_service import MRReviewerService
    from datetime import datetime
    import logging

    watcher = db.query(RepoWatcher).filter(RepoWatcher.id == watcher_id).first()
    if not watcher:
        return JSONResponse({"error": "Watcher not found"}, status_code=404)

    # Create service and poll
    service = MRReviewerService(db)

    try:
        logging.info(f"Starting poll for watcher {watcher.name} (provider: {watcher.provider})")
        reviews = await service.poll_watcher(watcher)
        # Update last_check timestamp
        watcher.last_check = datetime.utcnow()
        watcher.last_error = None
        db.commit()
        logging.info(f"Poll completed for watcher {watcher.name}: {len(reviews)} reviews")
        return {
            "id": watcher.id,
            "status": "poll_completed",
            "message": f"Found {len(reviews)} PRs to review",
            "reviews": len(reviews)
        }
    except Exception as e:
        import traceback
        logging.error(f"Poll error for watcher {watcher.name}: {e}\n{traceback.format_exc()}")
        watcher.last_error = str(e)
        watcher.last_check = datetime.utcnow()
        db.commit()
        return JSONResponse(
            {"error": str(e), "id": watcher.id, "status": "error"},
            status_code=500
        )


# ============== MR Reviews ==============

@router.get("/watchers/{watcher_id}/reviews")
async def get_watcher_reviews(
    request: Request,
    watcher_id: int,
    limit: int = 50,
    offset: int = 0,
    status: str = None,
    db: Session = Depends(get_db)
):
    """Get reviews for a watcher"""
    watcher = db.query(RepoWatcher).filter(RepoWatcher.id == watcher_id).first()
    if not watcher:
        return JSONResponse({"error": "Watcher not found"}, status_code=404)

    query = db.query(MRReview).filter(MRReview.watcher_id == watcher_id)

    if status:
        query = query.filter(MRReview.status == status)

    total = query.count()
    reviews = query.order_by(MRReview.created_at.desc()).offset(offset).limit(limit).all()

    # Return HTML partial for HTMX
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/review_list.html", {
            "request": request,
            "reviews": reviews,
            "watcher": watcher
        })

    return {
        "watcher_id": watcher_id,
        "total": total,
        "reviews": [
            {
                "id": r.id,
                "mr_iid": r.mr_iid,
                "mr_title": r.mr_title,
                "mr_url": r.mr_url,
                "source_branch": r.source_branch,
                "target_branch": r.target_branch,
                "mr_author": r.mr_author,
                "status": r.status,
                "diff_findings": r.diff_findings,
                "diff_summary": r.diff_summary,
                "diff_reviewed_at": r.diff_reviewed_at.isoformat() if r.diff_reviewed_at else None,
                "scan_id": r.scan_id,
                "scan_started_at": r.scan_started_at.isoformat() if r.scan_started_at else None,
                "scan_completed_at": r.scan_completed_at.isoformat() if r.scan_completed_at else None,
                "approval_status": r.approval_status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in reviews
        ]
    }


@router.get("/reviews/{review_id}")
async def get_review(review_id: int, db: Session = Depends(get_db)):
    """Get review details"""
    review = db.query(MRReview).filter(MRReview.id == review_id).first()
    if not review:
        return JSONResponse({"error": "Review not found"}, status_code=404)

    # Get finding counts from scan if available
    finding_count = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    if review.scan_id:
        findings = db.query(VerifiedFinding).filter(
            VerifiedFinding.scan_id == review.scan_id,
            VerifiedFinding.status == "complete"
        ).all()
        finding_count = len(findings)
        for f in findings:
            severity = (f.adjusted_severity or "").lower()
            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1
            elif severity == "medium":
                medium_count += 1
            elif severity == "low":
                low_count += 1

    return {
        "id": review.id,
        "watcher_id": review.watcher_id,
        "watcher_name": review.watcher.name if review.watcher else None,
        "mr_iid": review.mr_iid,
        "mr_title": review.mr_title,
        "mr_url": review.mr_url,
        "source_branch": review.source_branch,
        "target_branch": review.target_branch,
        "mr_author": review.mr_author,
        "status": review.status,
        "diff_findings": review.diff_findings,
        "diff_summary": review.diff_summary,
        "diff_reviewed_at": review.diff_reviewed_at.isoformat() if review.diff_reviewed_at else None,
        "scan_id": review.scan_id,
        "scan_started_at": review.scan_started_at.isoformat() if review.scan_started_at else None,
        "scan_completed_at": review.scan_completed_at.isoformat() if review.scan_completed_at else None,
        "finding_count": finding_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "comments_posted": review.comments_posted,
        "approval_status": review.approval_status,
        "last_error": review.last_error,
        "created_at": review.created_at.isoformat() if review.created_at else None,
    }


@router.post("/reviews/{review_id}/retry")
async def retry_review(
    review_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Retry a failed review"""
    review = db.query(MRReview).filter(MRReview.id == review_id).first()
    if not review:
        return JSONResponse({"error": "Review not found"}, status_code=404)

    if review.status not in ("error", "completed"):
        return JSONResponse({"error": "Can only retry errored or completed reviews"}, status_code=400)

    # Reset review state
    review.status = "pending"
    review.last_error = None
    db.commit()

    # Note: In a real implementation, this would re-queue the review for processing
    return {"id": review.id, "status": "retry_queued"}
