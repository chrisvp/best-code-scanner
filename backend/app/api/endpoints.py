from fastapi import APIRouter, Depends, Request, Form, BackgroundTasks, UploadFile, File, HTTPException, Body
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
    ScanProfile, ProfileAnalyzer, ProfileVerifier, WebhookConfig, WebhookDeliveryLog,
    RepoWatcher, MRReview, LLMRequestLog, GlobalSetting, VerificationVote, AgentSession
)
from app.models.auth_models import User, UserSession, FindingComment
from app.api.deps import get_current_user_optional, get_current_user

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

        # Get config (use latest if multiple exist)
        config = db.query(ScanConfig).filter(ScanConfig.scan_id == scan_id).order_by(ScanConfig.id.desc()).first()

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


async def run_revalidation_pipeline(scan_id: int, profile_id: int):
    """Run the revalidation pipeline (verification + enrichment) in background"""
    from app.services.orchestration.pipeline import ScanPipeline

    db = SessionLocal()
    try:
        # Update status
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        scan.status = "running"
        scan.logs = (scan.logs or "") + f"\n[Re-validation] Starting with profile {profile_id}\n"
        db.commit()

        # Get config (use latest if multiple exist)
        config = db.query(ScanConfig).filter(ScanConfig.scan_id == scan_id).order_by(ScanConfig.id.desc()).first()

        # Run pipeline from verification phase
        pipeline = ScanPipeline(scan_id, config, db)
        await pipeline.run_from_verification(profile_id=profile_id)

        # Update status
        scan.status = "completed"
        db.commit()

    except Exception as e:
        import traceback
        print(f"Revalidation pipeline error: {traceback.format_exc()}")
        db.rollback()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            scan.status = "failed"
            scan.logs = (scan.logs or "") + f"\nRevalidation Error: {str(e)}"
            db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Redirect to login if not authenticated
    if not current_user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/login", status_code=302)

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
        "profiles": profiles,
        "current_user": current_user
    })


@router.post("/scan/start")
async def start_scan(
    background_tasks: BackgroundTasks,
    target_url: str = Form(""),  # Optional if archive or copy_from_scan_id is provided
    archive: UploadFile = File(None),  # Optional file upload
    copy_from_scan_id: int = Form(None),  # Copy code from existing scan
    scan_name: str = Form(None),  # Optional custom display name for the scan
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
    # Validate: one of target_url, archive, or copy_from_scan_id must be provided
    has_archive = archive and archive.filename
    has_url = target_url and target_url.strip()
    has_copy_from = copy_from_scan_id is not None and copy_from_scan_id > 0
    if not has_archive and not has_url and not has_copy_from:
        raise HTTPException(status_code=400, detail="Either a Git URL, archive file, or source scan must be provided")

    # Handle copy from existing scan - just use the scan_name as display, source_scan_id is stored separately
    source_config = None
    if has_copy_from:
        source_scan = db.query(Scan).filter(Scan.id == copy_from_scan_id).first()
        if not source_scan:
            raise HTTPException(status_code=400, detail=f"Source scan {copy_from_scan_id} not found")
        # Load source scan's config to inherit settings like file_filter
        source_config = db.query(ScanConfig).filter(ScanConfig.scan_id == copy_from_scan_id).first()
        # Use custom scan_name if provided, otherwise show original source
        actual_target = scan_name if scan_name else f"rescan:{source_scan.target_url}"
    # Handle file upload if provided
    elif has_archive:
        # Save uploaded file to sandbox directory
        sandbox_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sandbox")
        os.makedirs(sandbox_dir, exist_ok=True)
        file_path = os.path.join(sandbox_dir, archive.filename)
        with open(file_path, "wb") as f:
            content = await archive.read()
            f.write(content)
        actual_target = file_path
    else:
        actual_target = target_url

    # Create Scan Record
    new_scan = Scan(target_url=actual_target, status="queued")
    db.add(new_scan)
    db.flush()

    # Create Scan Config - inherit file_filter from source scan if not explicitly provided
    inherited_file_filter = file_filter
    if not inherited_file_filter and source_config and source_config.file_filter:
        inherited_file_filter = source_config.file_filter

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
        file_filter=inherited_file_filter,
        profile_id=profile_id,
        source_scan_id=copy_from_scan_id if has_copy_from else None
    )
    db.add(config)
    db.commit()

    # Trigger Background Task
    background_tasks.add_task(run_pipeline, new_scan.id)

    # Return updated list via HTMX
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return templates.TemplateResponse("partials/scan_list.html", {"request": {}, "scans": scans})


@router.get("/scan/{scan_id}")
async def get_scan_details(request: Request, scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user_optional)):
    from app.models.scanner_models import ScanErrorLog, LLMRequestLog, ScanProfile, AgentSession
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return HTMLResponse(content="<h1>Scan not found</h1>", status_code=404)
    # Get recent errors for this scan (last 20)
    errors = db.query(ScanErrorLog).filter(
        ScanErrorLog.scan_id == scan_id
    ).order_by(ScanErrorLog.created_at.desc()).limit(20).all()
    # Get LLM request logs for this scan
    logs = db.query(LLMRequestLog).filter(
        LLMRequestLog.scan_id == scan_id
    ).order_by(LLMRequestLog.created_at.desc()).limit(200).all()
    # Get profiles for revalidate modal
    profiles = db.query(ScanProfile).filter(ScanProfile.enabled == True).order_by(ScanProfile.name).all()

    # Get draft findings with vote summaries
    draft_findings = db.query(DraftFinding).filter(
        DraftFinding.scan_id == scan_id
    ).order_by(DraftFinding.created_at.desc()).all()

    # Enrich drafts with vote counts and agent session info
    draft_data = []
    for draft in draft_findings:
        # Count votes by decision
        votes = db.query(VerificationVote).filter(
            VerificationVote.draft_finding_id == draft.id
        ).all()
        verify_count = sum(1 for v in votes if v.decision == 'VERIFY')
        weakness_count = sum(1 for v in votes if v.decision == 'WEAKNESS')
        reject_count = sum(1 for v in votes if v.decision == 'REJECT')
        abstain_count = sum(1 for v in votes if v.decision == 'ABSTAIN')

        # Check for agent session
        agent_session = db.query(AgentSession).filter(
            AgentSession.draft_finding_id == draft.id
        ).first()

        # Get file path from chunk
        file_path = None
        if draft.chunk_id:
            chunk = db.query(ScanFileChunk).filter(ScanFileChunk.id == draft.chunk_id).first()
            if chunk:
                scan_file = db.query(ScanFile).filter(ScanFile.id == chunk.scan_file_id).first()
                if scan_file:
                    file_path = scan_file.file_path

        draft_data.append({
            'draft': draft,
            'file_path': file_path,
            'verify_count': verify_count,
            'weakness_count': weakness_count,
            'reject_count': reject_count,
            'abstain_count': abstain_count,
            'total_votes': len(votes),
            'votes': votes,
            'agent_session': agent_session
        })

    return templates.TemplateResponse("scan_detail.html", {
        "request": request,
        "scan": scan,
        "errors": errors,
        "logs": logs,
        "profiles": profiles,
        "draft_data": draft_data,
        "current_user": current_user
    })


@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    """Get scan status for polling"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return JSONResponse({"error": "Scan not found"}, status_code=404)
    return JSONResponse({"status": scan.status})


@router.get("/scan/{scan_id}/logs-partial")
async def get_scan_logs_partial(request: Request, scan_id: int, db: Session = Depends(get_db)):
    """Get logs partial for HTMX refresh"""
    from app.models.scanner_models import LLMRequestLog
    logs = db.query(LLMRequestLog).filter(
        LLMRequestLog.scan_id == scan_id
    ).order_by(LLMRequestLog.created_at.desc()).limit(200).all()
    return templates.TemplateResponse("partials/scan_logs.html", {
        "request": request,
        "logs": logs
    })


@router.get("/scan/{scan_id}/draft/{draft_id}/agent-log")
async def get_draft_agent_log(scan_id: int, draft_id: int, db: Session = Depends(get_db)):
    """Get agent session log formatted as terminal output for a draft finding"""
    from app.models.scanner_models import AgentSession

    agent_session = db.query(AgentSession).filter(
        AgentSession.draft_finding_id == draft_id
    ).first()

    if not agent_session:
        return JSONResponse({"error": "No agent session found", "log": ""})

    # Format execution trace as terminal log
    log_lines = []
    log_lines.append(f"=== Agent Verification Session ===")
    log_lines.append(f"Model: {agent_session.model_name or 'unknown'}")
    log_lines.append(f"Status: {agent_session.status}")
    log_lines.append(f"Steps: {agent_session.total_steps}/{agent_session.max_steps}")
    if agent_session.duration_ms:
        log_lines.append(f"Duration: {agent_session.duration_ms / 1000:.1f}s")
    log_lines.append("")

    # Format execution trace
    if agent_session.execution_trace:
        for step in agent_session.execution_trace:
            step_num = step.get('step', '?')
            log_lines.append(f"--- Step {step_num} ---")

            thought = step.get('thought', '')
            if thought:
                # Truncate long thoughts
                if len(thought) > 500:
                    thought = thought[:500] + "..."
                log_lines.append(f"[Thought] {thought}")

            tool_name = step.get('tool_name')
            if tool_name:
                params = step.get('tool_params', {})
                log_lines.append(f"[Tool] {tool_name}({params})")

                result = step.get('tool_result', '')
                if result:
                    if len(result) > 300:
                        result = result[:300] + "..."
                    log_lines.append(f"[Result] {result}")

            log_lines.append("")

    # Final verdict
    if agent_session.verdict:
        log_lines.append("=== Final Verdict ===")
        log_lines.append(f"VERDICT: {agent_session.verdict}")
        if agent_session.confidence:
            log_lines.append(f"CONFIDENCE: {agent_session.confidence}%")
        if agent_session.reasoning:
            log_lines.append(f"REASONING: {agent_session.reasoning}")
        if agent_session.attack_path:
            log_lines.append(f"ATTACK PATH: {agent_session.attack_path}")

    if agent_session.error_message:
        log_lines.append(f"\n[ERROR] {agent_session.error_message}")

    return JSONResponse({
        "log": "\n".join(log_lines),
        "verdict": agent_session.verdict,
        "confidence": agent_session.confidence,
        "status": agent_session.status
    })


# ============ Finding Details & Chat ============

@router.get("/finding/{finding_id}", response_class=HTMLResponse)
async def get_finding_details(request: Request, finding_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user_optional)):
    """Get the finding details page with AI chat"""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return HTMLResponse(content="<h1>Finding not found</h1>", status_code=404)

    # Get global settings first (needed for chat model selection)
    global_settings = {row.key: row.value for row in db.query(GlobalSetting).all()}

    # Get available models for chat/fix based on chat_model_ids setting
    chat_model_ids_str = global_settings.get('chat_model_ids', '')
    if chat_model_ids_str:
        # Parse comma-separated IDs and fetch those models
        chat_model_ids = [int(id.strip()) for id in chat_model_ids_str.split(',') if id.strip().isdigit()]
        if chat_model_ids:
            models = db.query(ModelConfig).filter(ModelConfig.id.in_(chat_model_ids)).order_by(ModelConfig.name).all()
        else:
            models = []
    else:
        # Fallback to is_chat flag for backwards compatibility
        models = db.query(ModelConfig).filter(ModelConfig.is_chat == True).order_by(ModelConfig.name).all()

    # Get scan info if available
    scan = None
    if finding.scan_id:
        scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()

    # Get MR review info if available
    mr_review = None
    if finding.mr_review_id:
        mr_review = db.query(MRReview).filter(MRReview.id == finding.mr_review_id).first()

    # Get scan profiles for rescan dropdown
    profiles = db.query(ScanProfile).filter(ScanProfile.enabled == True).order_by(ScanProfile.name).all()

    # Get provenance data
    provenance = {
        "draft": None,
        "votes": [],
        "agent_sessions": []
    }

    if finding.draft_id:
        draft = db.query(DraftFinding).filter(DraftFinding.id == finding.draft_id).first()
        if draft:
            provenance["draft"] = draft
            provenance["votes"] = db.query(VerificationVote).filter(VerificationVote.draft_finding_id == draft.id).all()
            
    # Get agent sessions related to this finding or its draft
    agent_query_filter = AgentSession.finding_id == finding.id
    if finding.draft_id:
        agent_query_filter = (AgentSession.finding_id == finding.id) | (AgentSession.draft_finding_id == finding.draft_id)
        
    provenance["agent_sessions"] = db.query(AgentSession).filter(
        agent_query_filter
    ).order_by(AgentSession.created_at.desc()).all()

    return templates.TemplateResponse("finding_details.html", {
        "request": request,
        "finding": finding,
        "models": models,
        "scan": scan,
        "mr_review": mr_review,
        "profiles": profiles,
        "global_settings": global_settings,
        "provenance": provenance,
        "current_user": current_user
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


@router.post("/finding/{finding_id}/agent-verify")
async def agent_verify_finding(finding_id: int, model_id: int = Form(None), db: Session = Depends(get_db)):
    """Run agent-based verification on a finding"""
    from app.models.scanner_models import ScanFile, ScanFileChunk, AgentSession
    from app.services.orchestration.model_orchestrator import ModelPool

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return JSONResponse({"error": "Finding not found"}, status_code=404)

    # Get model for agent verification
    if model_id:
        model_config = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
    else:
        # Use first available model
        model_config = db.query(ModelConfig).first()

    if not model_config:
        return JSONResponse({"error": "No model available"}, status_code=400)

    # Get codebase root from scan
    codebase_path = None
    if finding.scan_id:
        scan_file = db.query(ScanFile).filter(ScanFile.scan_id == finding.scan_id).first()
        if scan_file:
            import os
            codebase_path = scan_file.file_path
            while codebase_path and os.path.basename(os.path.dirname(codebase_path)) != 'sandbox':
                codebase_path = os.path.dirname(codebase_path)
            if not codebase_path or not os.path.exists(codebase_path):
                codebase_path = f"sandbox/{finding.scan_id}"

    if not codebase_path or not os.path.exists(codebase_path):
        return JSONResponse({"error": f"Codebase not found at {codebase_path}"}, status_code=400)

    try:
        # Import agent verification components
        from app.services.intelligence.codebase_tools import CodebaseTools
        from app.services.intelligence.agent_runtime import AgenticVerifier

        # Create model pool
        db.expunge(model_config)  # Detach from session
        model_pool = ModelPool(model_config)
        await model_pool.start()

        # Initialize tools and verifier
        codebase_tools = CodebaseTools(
            scan_id=finding.scan_id,
            root_dir=codebase_path,
            db=db
        )

        # Get response format and tool call format from model config
        response_format = getattr(model_config, 'response_format', 'markers') or 'markers'
        tool_call_format = getattr(model_config, 'tool_call_format', 'none') or 'none'

        agentic_verifier = AgenticVerifier(
            model_pool=model_pool,
            tools=codebase_tools,
            max_steps=10,
            scan_id=finding.scan_id,
            finding_id=finding_id,
            response_format=response_format,
            tool_call_format=tool_call_format
        )

        # Run verification
        result = await agentic_verifier.verify(
            title=finding.description or "Unknown",
            vuln_type=finding.category or "Unknown",
            severity=finding.severity or "Medium",
            file_path=os.path.basename(finding.file_path) if finding.file_path else "unknown",
            line_number=finding.line_number or 0,
            snippet=finding.snippet or "",
            reason=finding.vulnerability_details or ""
        )
        
        # Update finding status based on verification
        if not result['verified']:
            finding.status = "FALSE_POSITIVE"
        else:
            finding.status = "VERIFIED"
        db.commit()

        await model_pool.stop()
        return JSONResponse(result)

    except ImportError as e:
        return JSONResponse({"error": f"Agent verification not available: {e}"}, status_code=500)
    except Exception as e:
        import traceback
        return JSONResponse({"error": str(e), "traceback": traceback.format_exc()}, status_code=500)


@router.get("/finding/{finding_id}/agent-verify/stream")
async def agent_verify_finding_stream(finding_id: int, model_id: int = None, db: Session = Depends(get_db)):
    """Run agent-based verification with SSE streaming of progress"""
    from app.models.scanner_models import ScanFile, AgentSession
    from app.services.orchestration.model_orchestrator import ModelPool
    from starlette.responses import StreamingResponse
    import asyncio
    import json as json_module

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return JSONResponse({"error": "Finding not found"}, status_code=404)

    # Get model for agent verification
    if model_id:
        model_config = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
    else:
        model_config = db.query(ModelConfig).first()

    if not model_config:
        return JSONResponse({"error": "No model available"}, status_code=400)

    # Get codebase root from scan
    codebase_path = None
    if finding.scan_id:
        scan_file = db.query(ScanFile).filter(ScanFile.scan_id == finding.scan_id).first()
        if scan_file:
            import os
            codebase_path = scan_file.file_path
            while codebase_path and os.path.basename(os.path.dirname(codebase_path)) != 'sandbox':
                codebase_path = os.path.dirname(codebase_path)
            if not codebase_path or not os.path.exists(codebase_path):
                codebase_path = f"sandbox/{finding.scan_id}"

    if not codebase_path or not os.path.exists(codebase_path):
        return JSONResponse({"error": f"Codebase not found"}, status_code=400)

    async def generate_events():
        step_queue = asyncio.Queue()

        def step_callback(step):
            """Called after each agent step - runs in same event loop, no thread-safety needed"""
            step_queue.put_nowait(step.to_dict())

        model_pool = None
        codebase_db = None
        try:
            from app.services.intelligence.codebase_tools import CodebaseTools
            from app.services.intelligence.agent_runtime import AgenticVerifier, AgentRuntime

            # Create model pool
            db_local = SessionLocal()
            model_cfg = db_local.query(ModelConfig).filter(ModelConfig.id == model_config.id).first()
            db_local.expunge(model_cfg)
            db_local.close()

            model_pool = ModelPool(model_cfg)
            await model_pool.start()

            codebase_db = SessionLocal()
            codebase_tools = CodebaseTools(
                scan_id=finding.scan_id,
                root_dir=codebase_path,
                db=codebase_db
            )

            # Get response format from model config
            response_format = getattr(model_cfg, 'response_format', 'markers') or 'markers'

            # Create runtime with callback
            runtime = AgentRuntime(
                model_pool=model_pool,
                tools=codebase_tools,
                max_steps=10,
                scan_id=finding.scan_id,
                finding_id=finding_id,
                step_callback=step_callback,
                response_format=response_format
            )

            # Start verification in background task
            async def run_verification():
                verifier = AgenticVerifier(
                    model_pool=model_pool,
                    tools=codebase_tools,
                    max_steps=10,
                    scan_id=finding.scan_id,
                    finding_id=finding_id,
                    response_format=response_format
                )
                # Override runtime to use callback
                verifier.runtime = runtime

                result = await verifier.verify(
                    title=finding.description or "Unknown",
                    vuln_type=finding.category or "Unknown",
                    severity=finding.severity or "Medium",
                    file_path=os.path.basename(finding.file_path) if finding.file_path else "unknown",
                    line_number=finding.line_number or 0,
                    snippet=finding.snippet or "",
                    reason=finding.vulnerability_details or ""
                )
                await model_pool.stop()
                return result

            verification_task = asyncio.create_task(run_verification())

            # Stream steps as they arrive
            while not verification_task.done():
                try:
                    step_data = await asyncio.wait_for(step_queue.get(), timeout=0.5)
                    yield f"data: {json_module.dumps({'type': 'step', 'step': step_data})}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive ping
                    yield f"data: {json_module.dumps({'type': 'ping'})}\n\n"

            # Drain any remaining steps from queue
            while not step_queue.empty():
                step_data = step_queue.get_nowait()
                yield f"data: {json_module.dumps({'type': 'step', 'step': step_data})}\n\n"

            # Get final result
            result = await verification_task
            
            # Update finding status based on verification
            db_update = SessionLocal()
            try:
                f_update = db_update.query(Finding).filter(Finding.id == finding_id).first()
                if f_update:
                    if not result['verified']:
                        f_update.status = "FALSE_POSITIVE"
                    else:
                        f_update.status = "VERIFIED"
                    db_update.commit()
            except Exception as e:
                print(f"Failed to update finding status: {e}")
            finally:
                db_update.close()

            yield f"data: {json_module.dumps({'type': 'result', 'success': True, 'verified': result['verified'], 'confidence': result['confidence'], 'reasoning': result.get('reasoning', ''), 'attack_path': result.get('attack_path', ''), 'session_id': result.get('session_id')})}\n\n"

        except Exception as e:
            import traceback
            traceback.print_exc()
            yield f"data: {json_module.dumps({'type': 'error', 'error': str(e)})}\n\n"

        finally:
            # Always cleanup resources
            if model_pool:
                try:
                    await model_pool.stop()
                except:
                    pass
            if codebase_db:
                codebase_db.close()

    return StreamingResponse(generate_events(), media_type="text/event-stream")


@router.get("/finding/{finding_id}/agent-sessions")
async def get_finding_agent_sessions(finding_id: int, db: Session = Depends(get_db)):
    """Get agent verification sessions for a finding"""
    from app.models.scanner_models import AgentSession

    sessions = db.query(AgentSession).filter(
        AgentSession.finding_id == finding_id
    ).order_by(AgentSession.created_at.desc()).all()

    return JSONResponse({
        "sessions": [
            {
                "id": s.id,
                "status": s.status,
                "verdict": s.verdict,
                "confidence": s.confidence,
                "reasoning": s.reasoning,
                "total_steps": s.total_steps,
                "duration_ms": s.duration_ms,
                "model_name": s.model_name,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "execution_trace": s.execution_trace
            }
            for s in sessions
        ]
    })


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


@router.post("/scan/{scan_id}/revalidate")
async def revalidate_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    profile_id: int = Form(...),
    db: Session = Depends(get_db)
):
    """Re-validate a scan's findings using a different profile's verifiers.

    This keeps the draft findings but:
    - Resets their status to pending
    - Deletes verified findings and final findings
    - Clears verification votes
    - Re-runs verification and enrichment with the selected profile
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    if scan.status == "running":
        return {"error": "Scan is already running"}

    # Verify profile exists and has verifiers
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    if not profile.verifiers:
        return {"error": "Profile has no verifiers configured"}

    # Delete verified findings and final findings
    db.query(Finding).filter(Finding.scan_id == scan_id).delete()
    db.query(VerifiedFinding).filter(VerifiedFinding.scan_id == scan_id).delete()

    # Clear verification votes for this scan
    db.query(VerificationVote).filter(VerificationVote.scan_id == scan_id).delete()

    # Reset draft findings to pending
    db.query(DraftFinding).filter(DraftFinding.scan_id == scan_id).update(
        {"status": "pending", "verification_votes": 0},
        synchronize_session=False
    )

    # Update scan status
    scan.status = "queued"
    scan.logs = (scan.logs or "") + f"\n[Re-validation] Queued with profile '{profile.name}' (ID: {profile_id})\n"
    db.commit()

    # Start revalidation pipeline
    background_tasks.add_task(run_revalidation_pipeline, scan_id, profile_id)

    return {
        "status": "revalidation_started",
        "scan_id": scan_id,
        "profile_id": profile_id,
        "profile_name": profile.name
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
            "status": scan.status if scan else "unknown",
            "current_phase": scan.current_phase if scan else None
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
    """Pause a running scan and immediately cancel all queued and running requests"""
    from app.services.orchestration.queue_manager import queue_manager

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan and scan.status == "running":
        scan.status = "paused"

        # Cancel all queued and running requests for this scan (immediate cancellation)
        queue_result = queue_manager.cancel_scan(scan_id, cancel_running=True)

        # Also mark pending/running LLM requests as cancelled in the database
        db_cancelled = db.query(LLMRequestLog).filter(
            LLMRequestLog.scan_id == scan_id,
            LLMRequestLog.status.in_(["pending", "running"])
        ).update({"status": "cancelled"}, synchronize_session=False)

        db.commit()

        return {
            "status": "paused",
            "scan_id": scan_id,
            "queue_cleared": queue_result["queued"],
            "running_cancelled": queue_result.get("running_cancelled", 0),
            "db_cancelled": db_cancelled
        }
    return {"error": "Cannot pause scan", "current_status": scan.status if scan else None}


@router.post("/scan/{scan_id}/resume")
async def resume_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Resume a paused scan"""
    from app.services.orchestration.checkpoint import ScanCheckpoint
    from app.services.orchestration.queue_manager import queue_manager

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan and scan.status == "paused":
        # Remove from cancelled set so new requests can proceed
        queue_manager.uncancelled_scan(scan_id)

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
    """Force stop a running or paused scan and cancel all queued requests"""
    from app.services.orchestration.queue_manager import queue_manager

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    if scan.status in ("running", "paused", "queued"):
        scan.status = "failed"
        scan.logs = (scan.logs or "") + "\n[STOPPED] Scan manually stopped by user"

        # Cancel all queued requests for this scan
        queue_result = queue_manager.cancel_scan(scan_id, cancel_running=True)

        # Also mark pending/running LLM requests as cancelled in the database
        db_cancelled = db.query(LLMRequestLog).filter(
            LLMRequestLog.scan_id == scan_id,
            LLMRequestLog.status.in_(["pending", "running"])
        ).update({"status": "cancelled"}, synchronize_session=False)

        db.commit()

        return {
            "status": "stopped",
            "scan_id": scan_id,
            "queue_cleared": queue_result["queued"],
            "db_cancelled": db_cancelled
        }
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
            "max_tokens": m.max_tokens,
            "max_context_length": getattr(m, 'max_context_length', 0) or 0,
            "max_concurrent": m.max_concurrent,
            "votes": m.votes,
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
        max_context_length=data.get('max_context_length', 0),
        max_concurrent=data.get('max_concurrent', 2),
        votes=data.get('votes', 1),
        chunk_size=data.get('chunk_size', 3000),
        response_format=data.get('response_format', 'markers'),
        tool_call_format=data.get('tool_call_format', 'none')
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
    if 'max_context_length' in data:
        model.max_context_length = data['max_context_length']
    if 'max_concurrent' in data:
        model.max_concurrent = data['max_concurrent']
    if 'votes' in data:
        model.votes = data['votes']
    if 'chunk_size' in data:
        model.chunk_size = data['chunk_size']
    if 'response_format' in data:
        model.response_format = data['response_format']
    if 'tool_call_format' in data:
        model.tool_call_format = data['tool_call_format']

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
        chunk_size=chunk_size
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


@router.get("/finding/{finding_id}/code-context")
async def get_code_context(finding_id: int, context_lines: int = 10, full_file: bool = False, db: Session = Depends(get_db)):
    """Get code context around the vulnerable line with line numbers.

    If full_file=true, returns entire file contents with vulnerable line marked.
    Falls back to snippet if file not found on filesystem.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return {"error": "Finding not found"}

    file_path = finding.file_path
    line_number = finding.line_number or 1

    # Try to find the actual file with fuzzy matching
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    possible_paths = [
        file_path,
        os.path.join(base_dir, file_path),
        os.path.join(base_dir, "sandbox", file_path),
    ]

    # Also try with scan_id prefix for sandbox files
    if finding.scan_id:
        possible_paths.append(os.path.join(base_dir, "sandbox", str(finding.scan_id), os.path.basename(file_path)))
        # Try stripping sandbox prefix if already included
        if file_path.startswith("sandbox/"):
            possible_paths.append(os.path.join(base_dir, file_path))

    actual_path = None
    for p in possible_paths:
        if os.path.exists(p):
            actual_path = p
            break

    if not actual_path:
        # Return just the snippet if file not found
        return {
            "lines": [{"number": line_number, "content": finding.snippet or "", "is_vulnerable": True}],
            "file_found": False,
            "total_lines": 1,
            "vulnerable_line": line_number
        }

    try:
        with open(actual_path, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines = f.readlines()

        total_lines = len(all_lines)

        if full_file:
            # Return entire file
            start = 0
            end = total_lines
        else:
            # Return context around vulnerable line
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
            "total_lines": total_lines,
            "vulnerable_line": line_number,
            "file_path": actual_path
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


@router.get("/finding/{finding_id}/agent-fix/stream")
async def agent_fix_stream(finding_id: int, model_id: int = None, db: Session = Depends(get_db)):
    """Generate a fix using agentic approach with SSE streaming of progress.

    This endpoint:
    1. Shows up in the queue system for slot management
    2. Streams progress events as the agent works
    3. Creates an AgentSession record for tracking
    """
    from app.models.scanner_models import AgentSession
    from app.services.orchestration.queue_manager import queue_manager, RequestType
    from starlette.responses import StreamingResponse
    import asyncio
    import json as json_module
    from datetime import datetime

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return JSONResponse({"error": "Finding not found"}, status_code=404)

    # Get model for fix generation
    if model_id:
        model_config = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
    else:
        # Get default chat model from global settings
        default_model_id = db.query(GlobalSetting).filter(
            GlobalSetting.key == "default_chat_model_id"
        ).first()
        if default_model_id and default_model_id.value:
            model_config = db.query(ModelConfig).filter(
                ModelConfig.id == int(default_model_id.value)
            ).first()
        else:
            model_config = db.query(ModelConfig).first()

    if not model_config:
        return JSONResponse({"error": "No model available"}, status_code=400)

    async def generate_events():
        # Yield immediately to prevent blocking the event loop before first data
        yield f"data: {json_module.dumps({'type': 'starting', 'finding_id': finding_id, 'model': model_config.name})}\n\n"

        # Small yield to let event loop process other requests
        await asyncio.sleep(0)

        step_queue = asyncio.Queue()
        start_time = datetime.now()

        def step_callback(step_data):
            """Called after each agent step - runs in same event loop, no thread-safety needed"""
            step_queue.put_nowait(step_data)

        # Create AgentSession and LLMRequestLog records for tracking (run in thread to not block)
        db_session = SessionLocal()
        request_log_id = None
        session_id = None
        try:
            agent_session = AgentSession(
                scan_id=finding.scan_id,
                finding_id=finding_id,
                status="running",
                model_name=model_config.name,
                task_prompt=f"Generate fix for finding: {finding.description[:200] if finding.description else 'Unknown'}"
            )
            db_session.add(agent_session)

            # Also create LLMRequestLog entry so it shows in the queue display
            request_log = LLMRequestLog(
                scan_id=finding.scan_id,
                model_name=model_config.name,
                phase="agent_fix",
                analyzer_name=f"Agent Fix (Finding #{finding_id})",
                file_path=finding.file_path,
                status="running"
            )
            db_session.add(request_log)
            db_session.commit()
            session_id = agent_session.id
            request_log_id = request_log.id
        except Exception as e:
            db_session.rollback()
            yield f"data: {json_module.dumps({'type': 'error', 'error': f'Failed to create session: {str(e)}'})}\n\n"
            return
        finally:
            db_session.close()

        db_local = None
        fix_task = None
        try:
            from app.services.fix_generator import FixGenerator

            # Create generator with step callback and identifiers for diff file naming
            db_local = SessionLocal()
            generator = FixGenerator(
                db_local,
                step_callback=step_callback,
                finding_id=finding_id,
                model_name=model_config.name
            )

            # Define the fix function for queue
            async def run_fix():
                return await generator.agent_fix(finding, model=model_config.name)

            # Run through queue manager for slot tracking
            # Note: scan_id=None because agent fix is user-initiated and independent of scan state
            fix_task = asyncio.create_task(
                queue_manager.enqueue(
                    model_name=model_config.name,
                    request_type=RequestType.AGENT,
                    func=run_fix,
                    max_concurrent=model_config.max_concurrent or 2,
                    scan_id=None,
                    finding_id=finding_id,
                    description=f"Agent fix for finding #{finding_id}"
                )
            )

            # Stream steps as they arrive with overall timeout (30 min max)
            step_count = 0
            overall_timeout = 1800  # 30 minutes
            elapsed = 0
            while not fix_task.done() and elapsed < overall_timeout:
                try:
                    step_data = await asyncio.wait_for(step_queue.get(), timeout=0.5)
                    step_count += 1
                    yield f"data: {json_module.dumps({'type': 'step', 'step': step_data})}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive ping
                    yield f"data: {json_module.dumps({'type': 'ping'})}\n\n"
                elapsed = (datetime.now() - start_time).total_seconds()

            if elapsed >= overall_timeout:
                fix_task.cancel()
                yield f"data: {json_module.dumps({'type': 'error', 'error': 'Agent fix timed out after 30 minutes'})}\n\n"
                return

            # Drain any remaining steps from queue
            while not step_queue.empty():
                step_data = step_queue.get_nowait()
                step_count += 1
                yield f"data: {json_module.dumps({'type': 'step', 'step': step_data})}\n\n"

            # Get final result
            result = await fix_task

            if result is None:
                # Task was cancelled or skipped
                yield f"data: {json_module.dumps({'type': 'error', 'error': 'Task was cancelled or skipped'})}\n\n"
                return

            fix = result.get("fix", "")
            reasoning = result.get("reasoning", [])
            iterations = result.get("iterations", 0)
            diff_file = result.get("diff_file")  # Path to saved diff file

            # Calculate duration
            end_time = datetime.now()
            duration_ms = (end_time - start_time).total_seconds() * 1000

            db_save = SessionLocal()
            try:
                has_fix = bool(fix) or bool(diff_file)
                fix_id = None
                fix_count = 0

                # Save GeneratedFix if successful
                if has_fix:
                    generated_fix = GeneratedFix(
                        finding_id=finding_id,
                        model_name=model_config.name,
                        code=fix if fix else f"Diff saved to: {diff_file}",
                        reasoning=json_module.dumps(reasoning) if reasoning else None
                    )
                    db_save.add(generated_fix)

                    # Update finding's corrected_code
                    finding_to_update = db_save.query(Finding).filter(Finding.id == finding_id).first()
                    if finding_to_update:
                        finding_to_update.corrected_code = fix if fix else f"Diff saved to: {diff_file}"

                    fix_id = generated_fix.id

                # Update AgentSession with results
                session_to_update = db_save.query(AgentSession).filter(AgentSession.id == session_id).first()
                if session_to_update:
                    session_to_update.status = "completed" if has_fix else "failed"
                    session_to_update.verdict = "FIX_GENERATED" if has_fix else "NO_FIX"
                    session_to_update.reasoning = json_module.dumps(reasoning) if reasoning else None
                    session_to_update.total_steps = step_count
                    session_to_update.duration_ms = duration_ms
                    session_to_update.completed_at = end_time
                    # Store diff file path in attack_path field (reusing existing column)
                    if diff_file:
                        session_to_update.attack_path = diff_file

                # Update LLMRequestLog to mark as completed
                if request_log_id:
                    request_log_update = db_save.query(LLMRequestLog).filter(LLMRequestLog.id == request_log_id).first()
                    if request_log_update:
                        request_log_update.status = "completed" if has_fix else "failed"
                        request_log_update.duration_ms = duration_ms

                db_save.commit()
                fix_count = db_save.query(GeneratedFix).filter(GeneratedFix.finding_id == finding_id).count()
            except Exception as e:
                db_save.rollback()
                print(f"Error saving fix: {e}")
            finally:
                db_save.close()

            # Send final result
            yield f"data: {json_module.dumps({'type': 'result', 'success': has_fix, 'corrected_code': fix, 'diff_file': diff_file, 'reasoning': reasoning, 'iterations': iterations, 'fix_id': fix_id, 'fix_count': fix_count, 'session_id': session_id, 'duration_ms': duration_ms})}\n\n"

        except Exception as e:
            import traceback
            traceback.print_exc()

            # Update session and request log as failed
            db_err = SessionLocal()
            try:
                if session_id:
                    session_err = db_err.query(AgentSession).filter(AgentSession.id == session_id).first()
                    if session_err:
                        session_err.status = "failed"
                        session_err.error_message = str(e)
                        session_err.completed_at = datetime.now()

                # Also update LLMRequestLog
                if request_log_id:
                    request_log_err = db_err.query(LLMRequestLog).filter(LLMRequestLog.id == request_log_id).first()
                    if request_log_err:
                        request_log_err.status = "failed"
                        request_log_err.parse_error = str(e)

                db_err.commit()
            except:
                db_err.rollback()
            finally:
                db_err.close()

            yield f"data: {json_module.dumps({'type': 'error', 'error': str(e)})}\n\n"

        finally:
            # Always close db_local if it was opened
            if db_local:
                db_local.close()
            # Cancel task if still running
            if fix_task and not fix_task.done():
                fix_task.cancel()

    return StreamingResponse(generate_events(), media_type="text/event-stream")


@router.get("/finding/{finding_id}/diff-files")
async def get_finding_diff_files(finding_id: int, db: Session = Depends(get_db)):
    """Get list of available diff files for a finding.

    Diff files are stored next to the original source file with naming:
    {original_file}.fix.{findingId}.{model}.diff
    """
    import glob

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return {"error": "Finding not found", "diff_files": []}

    if not finding.file_path or not os.path.exists(finding.file_path):
        return {"error": "Source file not found", "diff_files": []}

    # Look for diff files matching pattern: {file}.fix.{findingId}.*.diff
    pattern = f"{finding.file_path}.fix.{finding_id}.*.diff"
    diff_files = glob.glob(pattern)

    results = []
    for diff_path in diff_files:
        try:
            # Extract model name from filename
            # Pattern: file.c.fix.123.model_name.diff
            basename = os.path.basename(diff_path)
            parts = basename.split(f'.fix.{finding_id}.')
            if len(parts) == 2:
                model_part = parts[1].replace('.diff', '')
            else:
                model_part = 'unknown'

            # Get file stats
            stat = os.stat(diff_path)

            results.append({
                "path": diff_path,
                "filename": basename,
                "model": model_part,
                "size": stat.st_size,
                "created": stat.st_mtime
            })
        except Exception as e:
            continue

    # Sort by creation time, newest first
    results.sort(key=lambda x: x['created'], reverse=True)

    return {"diff_files": results}


@router.get("/finding/{finding_id}/diff-file/{model}")
async def get_diff_file_content(finding_id: int, model: str, db: Session = Depends(get_db)):
    """Get the content of a specific diff file."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return {"error": "Finding not found"}

    if not finding.file_path:
        return {"error": "Source file not found"}

    # Build the expected diff file path
    import re
    model_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', model)
    diff_path = f"{finding.file_path}.fix.{finding_id}.{model_safe}.diff"

    if not os.path.exists(diff_path):
        return {"error": f"Diff file not found: {diff_path}"}

    try:
        with open(diff_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return {
            "path": diff_path,
            "model": model,
            "content": content
        }
    except Exception as e:
        return {"error": f"Error reading diff file: {str(e)}"}


@router.post("/finding/{finding_id}/reparse")
async def reparse_finding(finding_id: int, request: Request, db: Session = Depends(get_db)):
    """
    Re-run the enrichment step for a finding.
    This re-generates the full security report from the verified finding using the enricher.
    """
    from app.services.analysis.enricher import FindingEnricher
    from app.services.orchestration.model_orchestrator import ModelPool
    from app.models.scanner_models import VerifiedFinding

    # Get the finding
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return {"error": "Finding not found"}

    if not finding.verified_id:
        return {"error": "This finding has no verified_id, cannot re-enrich"}

    # Get the verified finding
    verified = db.query(VerifiedFinding).filter(VerifiedFinding.id == finding.verified_id).first()
    if not verified:
        return {"error": "Verified finding not found"}

    # Get any available model for enrichment
    enrichment_model = db.query(ModelConfig).first()

    if not enrichment_model:
        return {"error": "No models found. Configure at least one model."}

    try:
        # Get output mode from model config (response_format column)
        # Maps: "markers" -> "markers", "json_schema" -> "guided_json", None -> "markers"
        model_response_format = enrichment_model.response_format or "markers"
        if model_response_format == "json_schema":
            output_mode = "guided_json"
        else:
            output_mode = model_response_format

        # Detach config from session to avoid refresh errors
        db.expunge(enrichment_model)

        # Create a model pool for the enrichment model
        model_pool = ModelPool(enrichment_model)
        await model_pool.start()

        # Create enricher and re-run enrichment with model's configured output mode
        enricher = FindingEnricher(model_pool, db, output_mode=output_mode, json_schema=None)
        enriched = await enricher.enrich_single(verified)

        await model_pool.stop()

        if not enriched:
            return {"error": "Enrichment returned empty result"}

        # Update the finding with new enriched data
        import re
        updates = {}
        if enriched.get('finding'):
            finding.description = enriched['finding']
            updates['description'] = enriched['finding'][:50] + "..."
        if enriched.get('category'):
            finding.category = enriched['category']
            updates['category'] = enriched['category']
        if enriched.get('severity'):
            finding.severity = enriched['severity']
            updates['severity'] = enriched['severity']
        if enriched.get('cvss'):
            try:
                cvss_str = enriched['cvss']
                # Extract numeric part
                match = re.search(r'(\d+\.?\d*)', cvss_str)
                if match:
                    finding.cvss_score = float(match.group(1))
                    updates['cvss_score'] = finding.cvss_score
            except:
                pass
        if enriched.get('impacted_code'):
            finding.snippet = enriched['impacted_code']
            updates['snippet'] = "updated"
        if enriched.get('vulnerability_details'):
            finding.vulnerability_details = enriched['vulnerability_details']
            updates['vulnerability_details'] = "updated"
        if enriched.get('proof_of_concept'):
            finding.proof_of_concept = enriched['proof_of_concept']
            updates['proof_of_concept'] = "updated"
        if enriched.get('remediation_steps'):
            finding.remediation_steps = enriched['remediation_steps']
            updates['remediation_steps'] = "updated"
        if enriched.get('references'):
            finding.references = enriched['references']
            updates['references'] = "updated"

        db.commit()

        return {
            "success": True,
            "updates": updates,
            "message": f"Successfully re-enriched finding with {len(updates)} fields updated"
        }

    except Exception as e:
        import traceback
        print(f"Reparse error: {traceback.format_exc()}")
        return {"error": str(e)}


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
async def get_config(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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

    # Get global settings
    global_settings = {s.key: s.value for s in db.query(GlobalSetting).all()}

    return templates.TemplateResponse("config.html", {
        "request": request,
        "settings": settings,
        "models": models,
        "profiles": profiles,
        "rules": rules,
        "gitlab_repos": gitlab_repos,
        "global_settings": global_settings,
        "current_user": current_user
    })


@router.post("/config")
async def update_config(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    form_type: str = Form(None),
    llm_base_url: str = Form(None),
    llm_api_key: str = Form(None),
    llm_verify_ssl: bool = Form(False),
    max_concurrent: int = Form(None),
    scanner_url_prefix: str = Form(None),
    joern_docker_image: str = Form(None),
    joern_timeout: int = Form(None)
):
    from app.core.config import settings
    message = "Configuration saved!"

    if form_type == "joern":
        if joern_docker_image:
            settings.JOERN_DOCKER_IMAGE = joern_docker_image
            GlobalSetting.set(db, "joern_docker_image", joern_docker_image, description="Joern Docker image")
        if joern_timeout:
            settings.JOERN_TIMEOUT = joern_timeout
            GlobalSetting.set(db, "joern_timeout", joern_timeout, "int", "Joern operation timeout (seconds)")
        message = "Joern settings saved!"

    elif form_type == "connection":
        if llm_base_url:
            settings.LLM_BASE_URL = llm_base_url
            GlobalSetting.set(db, "llm_base_url", llm_base_url, description="LLM API base URL")
        if llm_api_key:
            settings.LLM_API_KEY = llm_api_key
            GlobalSetting.set(db, "llm_api_key", llm_api_key, description="LLM API key")
        settings.LLM_VERIFY_SSL = llm_verify_ssl
        GlobalSetting.set(db, "llm_verify_ssl", str(llm_verify_ssl).lower(), "bool", "Verify SSL certificates")

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

    from app.models.scanner_models import GitLabRepo

    models = db.query(ModelConfig).all()
    profiles = db.query(ScanProfile).order_by(ScanProfile.name).all()
    rules = db.query(StaticRule).order_by(StaticRule.severity, StaticRule.name).all()
    gitlab_repos = db.query(GitLabRepo).order_by(GitLabRepo.name).all()
    global_settings = {s.key: s.value for s in db.query(GlobalSetting).all()}

    return templates.TemplateResponse("config.html", {
        "request": request,
        "settings": settings,
        "models": models,
        "profiles": profiles,
        "rules": rules,
        "gitlab_repos": gitlab_repos,
        "global_settings": global_settings,
        "message": message
    })


# ============== Joern Test ==============

@router.get("/joern/test")
async def test_joern_connection(current_user: User = Depends(get_current_user)):
    """Test if Joern Docker is available and working.

    Security: Uses asyncio.create_subprocess_exec with argument lists (not shell).
    The docker image name comes from server config, not user input.
    Requires authentication.
    """
    import asyncio
    from app.core.config import settings

    result = {
        "docker_available": False,
        "image_available": False,
        "joern_working": False,
        "version": None,
        "error": None,
        "image": settings.JOERN_DOCKER_IMAGE
    }

    try:
        # Check if docker is available (safe: no user input, exec not shell)
        proc = await asyncio.create_subprocess_exec(
            "docker", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        if proc.returncode == 0:
            result["docker_available"] = True
            result["docker_version"] = stdout.decode().strip()
        else:
            result["error"] = "Docker not available"
            return result

        # Check if image exists locally (safe: image from config, exec not shell)
        proc = await asyncio.create_subprocess_exec(
            "docker", "images", "-q", settings.JOERN_DOCKER_IMAGE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        if stdout.decode().strip():
            result["image_available"] = True
        else:
            result["error"] = f"Image not found: {settings.JOERN_DOCKER_IMAGE}. Run: docker pull {settings.JOERN_DOCKER_IMAGE}"
            return result

        # Test Joern works (safe: image from config, exec not shell)
        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "--rm", settings.JOERN_DOCKER_IMAGE, "joern", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode == 0:
            result["joern_working"] = True
            result["version"] = stdout.decode().strip().split('\n')[0]
        else:
            result["error"] = f"Joern failed: {stderr.decode()}"

    except asyncio.TimeoutError:
        result["error"] = "Timeout waiting for Docker/Joern"
    except Exception as e:
        result["error"] = str(e)

    return result


# ============== Static Rules Management ==============

@router.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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

# ============== Scan Profiles Management ==============

def seed_default_profiles(db: Session):
    """Seed default scan profiles if they don't exist"""
    from app.services.analysis.prompts import PROMPTS

    # Check if any profiles exist
    existing = db.query(ScanProfile).count()
    if existing > 0:
        return

    # Get default model - required for creating profiles
    default_model = db.query(ModelConfig).first()
    if not default_model:
        # Can't create profiles without at least one model
        print("Skipping profile seeding - no models configured yet")
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
async def profiles_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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
        "enricher_model_id": profile.enricher_model_id,
        "enricher_model_name": profile.enricher_model.name if profile.enricher_model else None,
        "verification_threshold": profile.verification_threshold,
        "require_unanimous_reject": profile.require_unanimous_reject,
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
        ],
        "verifiers": [
            {
                "id": v.id,
                "name": v.name,
                "description": v.description,
                "model_id": v.model_id,
                "model_name": v.model.name if v.model else None,
                "prompt_template": v.prompt_template,
                "vote_weight": v.vote_weight,
                "min_confidence": v.min_confidence,
                "run_order": v.run_order,
                "enabled": v.enabled,
            }
            for v in profile.verifiers
        ]
    }


@router.post("/profiles")
def create_profile(
    name: str = Form(...),
    description: str = Form(None),
    chunk_size: int = Form(6000),
    chunk_strategy: str = Form("smart"),
    first_phase_method: str = Form("hybrid"),
    joern_query_set: str = Form("default"),
    joern_chunk_strategy: str = Form("directory"),
    joern_max_files_per_cpg: int = Form(100),
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
        first_phase_method=first_phase_method,
        joern_query_set=joern_query_set,
        joern_chunk_strategy=joern_chunk_strategy,
        joern_max_files_per_cpg=joern_max_files_per_cpg,
        enabled=True
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)

    return {"id": profile.id, "name": profile.name, "status": "created"}


@router.put("/profiles/{profile_id}")
def update_profile(
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
def delete_profile(profile_id: int, db: Session = Depends(get_db)):
    """Delete a scan profile and its analyzers"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    # Delete analyzers first
    db.query(ProfileAnalyzer).filter(ProfileAnalyzer.profile_id == profile_id).delete()
    db.delete(profile)
    db.commit()

    return {"status": "deleted", "id": profile_id}


@router.put("/profiles/{profile_id}/phase-method")
def update_profile_phase_method(
    profile_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a profile's first phase method (llm, joern, hybrid)"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    method = data.get("first_phase_method")
    if method not in ("llm", "joern", "hybrid"):
        return {"error": "Invalid phase method. Must be: llm, joern, or hybrid"}

    profile.first_phase_method = method
    db.commit()

    return {"status": "updated", "id": profile_id, "first_phase_method": method}


@router.put("/profiles/{profile_id}/joern-query-set")
def update_profile_joern_query_set(
    profile_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a profile's Joern query set"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    query_set = data.get("joern_query_set")
    valid_sets = ("default", "uefi", "memory", "injection", "all")
    if query_set not in valid_sets:
        return {"error": f"Invalid query set. Must be one of: {', '.join(valid_sets)}"}

    profile.joern_query_set = query_set
    db.commit()

    return {"status": "updated", "id": profile_id, "joern_query_set": query_set}


@router.post("/profiles/{profile_id}/duplicate")
def duplicate_profile(profile_id: int, db: Session = Depends(get_db)):
    """Duplicate a scan profile with all its analyzers and verifiers"""
    from app.models.scanner_models import ProfileVerifier

    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    # Generate unique name for the copy
    base_name = f"{profile.name} (Copy)"
    name = base_name
    counter = 1
    while db.query(ScanProfile).filter(ScanProfile.name == name).first():
        counter += 1
        name = f"{profile.name} (Copy {counter})"

    # Create new profile with copied settings
    new_profile = ScanProfile(
        name=name,
        description=profile.description,
        is_default=False,  # Don't copy default status
        chunk_size=profile.chunk_size,
        chunk_strategy=profile.chunk_strategy,
        enricher_model_id=profile.enricher_model_id,
        enricher_prompt_template=profile.enricher_prompt_template,
        agentic_verifier_mode=profile.agentic_verifier_mode,
        agentic_verifier_model_id=profile.agentic_verifier_model_id,
        agentic_verifier_max_steps=profile.agentic_verifier_max_steps,
        verification_threshold=profile.verification_threshold,
        require_unanimous_reject=profile.require_unanimous_reject,
        enabled=profile.enabled,
    )
    db.add(new_profile)
    db.flush()  # Get the ID for the new profile

    # Copy analyzers
    for analyzer in profile.analyzers:
        new_analyzer = ProfileAnalyzer(
            profile_id=new_profile.id,
            name=analyzer.name,
            description=analyzer.description,
            model_id=analyzer.model_id,
            chunk_size=analyzer.chunk_size,
            prompt_template=analyzer.prompt_template,
            file_filter=analyzer.file_filter,
            language_filter=analyzer.language_filter,
            role=analyzer.role,
            run_order=analyzer.run_order,
            enabled=analyzer.enabled,
            stop_on_findings=analyzer.stop_on_findings,
            min_severity_to_report=analyzer.min_severity_to_report,
        )
        db.add(new_analyzer)

    # Copy verifiers
    for verifier in profile.verifiers:
        new_verifier = ProfileVerifier(
            profile_id=new_profile.id,
            name=verifier.name,
            description=verifier.description,
            model_id=verifier.model_id,
            prompt_template=verifier.prompt_template,
            run_order=verifier.run_order,
            enabled=verifier.enabled,
        )
        db.add(new_verifier)

    db.commit()

    return {
        "status": "duplicated",
        "id": new_profile.id,
        "name": new_profile.name,
        "analyzers_count": len(profile.analyzers),
        "verifiers_count": len(profile.verifiers),
    }


@router.post("/profiles/{profile_id}/analyzers")
def add_analyzer(
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
        min_severity_to_report=min_severity_to_report,
    )
    db.add(analyzer)
    db.commit()
    db.refresh(analyzer)

    return {"id": analyzer.id, "name": analyzer.name, "status": "created"}


@router.put("/profiles/{profile_id}/analyzers/{analyzer_id}")
def update_analyzer(
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
def delete_analyzer(profile_id: int, analyzer_id: int, db: Session = Depends(get_db)):
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
def toggle_analyzer(profile_id: int, analyzer_id: int, db: Session = Depends(get_db)):
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


# ============== Profile Verifiers ==============

@router.post("/profiles/{profile_id}/verifiers")
def add_verifier(
    profile_id: int,
    request: Request,
    name: str = Form(...),
    model_id: int = Form(...),
    prompt_template: str = Form(None),
    vote_weight: float = Form(1.0),
    min_confidence: int = Form(0),
    run_order: int = Form(1),
    description: str = Form(None),
    db: Session = Depends(get_db)
):
    """Add a verifier to a profile"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    verifier = ProfileVerifier(
        profile_id=profile_id,
        name=name,
        model_id=model_id,
        prompt_template=prompt_template,
        vote_weight=vote_weight,
        min_confidence=min_confidence,
        run_order=run_order,
        description=description,
        enabled=True,
    )
    db.add(verifier)
    db.commit()

    return {"id": verifier.id, "name": verifier.name, "status": "created"}


@router.put("/profiles/{profile_id}/verifiers/{verifier_id}")
def update_verifier(
    profile_id: int,
    verifier_id: int,
    name: str = Form(None),
    prompt_template: str = Form(None),
    model_id: int = Form(None),
    vote_weight: float = Form(None),
    min_confidence: int = Form(None),
    run_order: int = Form(None),
    description: str = Form(None),
    enabled: bool = Form(None),
    db: Session = Depends(get_db)
):
    """Update a verifier"""
    verifier = db.query(ProfileVerifier).filter(
        ProfileVerifier.id == verifier_id,
        ProfileVerifier.profile_id == profile_id
    ).first()
    if not verifier:
        return {"error": "Verifier not found"}

    if name is not None:
        verifier.name = name
    if prompt_template is not None:
        verifier.prompt_template = prompt_template
    if model_id is not None:
        verifier.model_id = model_id
    if vote_weight is not None:
        verifier.vote_weight = vote_weight
    if min_confidence is not None:
        verifier.min_confidence = min_confidence
    if run_order is not None:
        verifier.run_order = run_order
    if description is not None:
        verifier.description = description
    if enabled is not None:
        verifier.enabled = enabled

    db.commit()
    return {"id": verifier.id, "name": verifier.name, "status": "updated"}


@router.delete("/profiles/{profile_id}/verifiers/{verifier_id}")
def delete_verifier(profile_id: int, verifier_id: int, db: Session = Depends(get_db)):
    """Delete a verifier from a profile"""
    verifier = db.query(ProfileVerifier).filter(
        ProfileVerifier.id == verifier_id,
        ProfileVerifier.profile_id == profile_id
    ).first()
    if not verifier:
        return {"error": "Verifier not found"}

    db.delete(verifier)
    db.commit()

    return {"status": "deleted", "id": verifier_id}


@router.post("/profiles/{profile_id}/verifiers/{verifier_id}/toggle")
def toggle_verifier(profile_id: int, verifier_id: int, db: Session = Depends(get_db)):
    """Toggle a verifier's enabled status"""
    verifier = db.query(ProfileVerifier).filter(
        ProfileVerifier.id == verifier_id,
        ProfileVerifier.profile_id == profile_id
    ).first()
    if not verifier:
        return {"error": "Verifier not found"}

    verifier.enabled = not verifier.enabled
    db.commit()

    return {"id": verifier.id, "enabled": verifier.enabled}


# ============== Profile Enricher ==============

@router.put("/profiles/{profile_id}/enricher")
def update_profile_enricher(
    profile_id: int,
    enricher_model_id: int = Form(None),
    enricher_prompt_template: str = Form(None),
    db: Session = Depends(get_db)
):
    """Update a profile's enricher configuration"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    # Allow null/empty to clear the enricher
    profile.enricher_model_id = enricher_model_id if enricher_model_id else None
    if enricher_prompt_template is not None:
        profile.enricher_prompt_template = enricher_prompt_template if enricher_prompt_template else None

    db.commit()
    return {"status": "updated", "enricher_model_id": profile.enricher_model_id}


# ============== Profile Agentic Verifier ==============

@router.put("/profiles/{profile_id}/agentic-verifier")
def update_profile_agentic_verifier(
    profile_id: int,
    agentic_verifier_mode: str = Form("skip"),
    agentic_verifier_model_id: int = Form(None),
    agentic_verifier_max_steps: int = Form(8),
    db: Session = Depends(get_db)
):
    """Update a profile's agentic verifier configuration"""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return {"error": "Profile not found"}

    # Validate mode
    if agentic_verifier_mode not in ("skip", "hybrid", "full"):
        return {"error": "Invalid mode. Must be 'skip', 'hybrid', or 'full'"}

    profile.agentic_verifier_mode = agentic_verifier_mode
    profile.agentic_verifier_model_id = agentic_verifier_model_id if agentic_verifier_model_id else None
    profile.agentic_verifier_max_steps = max(3, min(20, agentic_verifier_max_steps))

    db.commit()
    return {
        "status": "updated",
        "agentic_verifier_mode": profile.agentic_verifier_mode,
        "agentic_verifier_model_id": profile.agentic_verifier_model_id,
        "agentic_verifier_max_steps": profile.agentic_verifier_max_steps
    }


@router.put("/profiles/{profile_id}/agent-models")
def update_profile_agent_models(
    profile_id: int,
    data: dict = Body(...),
    db: Session = Depends(get_db)
):
    """Update a profile's agent models (multiple models for agent verification)"""
    from app.models.scanner_models import ProfileAgentModel

    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        return JSONResponse({"error": "Profile not found"}, status_code=404)

    model_ids = data.get("model_ids", [])

    # Convert to integers
    model_ids = [int(mid) for mid in model_ids if mid]

    # Delete existing agent models for this profile
    db.query(ProfileAgentModel).filter(ProfileAgentModel.profile_id == profile_id).delete()

    # Add new agent models
    for model_id in model_ids:
        # Verify model exists and supports tool calling
        model = db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
        if model and model.tool_call_format and model.tool_call_format != "none":
            agent_model = ProfileAgentModel(
                profile_id=profile_id,
                model_id=model_id,
                enabled=True
            )
            db.add(agent_model)

    db.commit()

    # Return current agent models
    agent_models = db.query(ProfileAgentModel).filter(ProfileAgentModel.profile_id == profile_id).all()
    return {
        "status": "updated",
        "agent_model_ids": [am.model_id for am in agent_models]
    }


# ============== Global Settings ==============

@router.get("/settings")
async def get_global_settings(db: Session = Depends(get_db)):
    """Get all global settings"""
    settings = db.query(GlobalSetting).all()
    return {s.key: {"value": s.value, "type": s.value_type, "description": s.description} for s in settings}


@router.get("/settings/{key}")
async def get_setting(key: str, db: Session = Depends(get_db)):
    """Get a specific global setting"""
    setting = db.query(GlobalSetting).filter(GlobalSetting.key == key).first()
    if not setting:
        return {"error": "Setting not found"}
    return {"key": setting.key, "value": setting.value, "type": setting.value_type, "description": setting.description}


@router.put("/settings/{key}")
async def update_setting(
    key: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update a global setting (accepts JSON body with 'value' field)"""
    body = await request.json()
    value = str(body.get('value', ''))
    value_type = body.get('value_type', 'string')
    description = body.get('description')

    setting = db.query(GlobalSetting).filter(GlobalSetting.key == key).first()
    if not setting:
        # Create new setting
        setting = GlobalSetting(key=key)
        db.add(setting)

    setting.value = value
    setting.value_type = value_type
    if description:
        setting.description = description

    db.commit()
    return {"key": setting.key, "value": setting.value, "status": "updated"}


@router.post("/settings")
async def create_setting(
    key: str = Form(...),
    value: str = Form(...),
    value_type: str = Form("string"),
    description: str = Form(None),
    db: Session = Depends(get_db)
):
    """Create a new global setting"""
    existing = db.query(GlobalSetting).filter(GlobalSetting.key == key).first()
    if existing:
        return {"error": "Setting already exists"}

    setting = GlobalSetting(
        key=key,
        value=value,
        value_type=value_type,
        description=description
    )
    db.add(setting)
    db.commit()
    return {"key": setting.key, "value": setting.value, "status": "created"}


@router.get("/output-templates")
async def get_output_templates():
    """Get all output format templates (with DB overrides applied)"""
    from app.services.analysis.output_formats import get_all_templates
    return get_all_templates()


@router.put("/output-templates/{role}/{mode}")
async def update_output_template(
    role: str,
    mode: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update an output format template"""
    from app.services.analysis.output_formats import invalidate_template_cache

    if role not in ["analyzer", "verifier", "enricher"]:
        return {"error": "Invalid role. Must be: analyzer, verifier, or enricher"}
    if mode not in ["markers", "json", "guided_json"]:
        return {"error": "Invalid mode. Must be: markers, json, or guided_json"}

    body = await request.json()
    value = body.get('value', '')
    key = f"output_format_{role}_{mode}"

    # Update or create the setting
    setting = db.query(GlobalSetting).filter(GlobalSetting.key == key).first()
    if not setting:
        setting = GlobalSetting(key=key, value_type="string")
        db.add(setting)

    setting.value = value
    db.commit()

    # Invalidate cache so new value takes effect
    invalidate_template_cache()

    return {"key": key, "status": "updated"}


@router.delete("/output-templates/{role}/{mode}")
async def reset_output_template(
    role: str,
    mode: str,
    db: Session = Depends(get_db)
):
    """Reset an output format template to default (delete DB override)"""
    from app.services.analysis.output_formats import invalidate_template_cache

    key = f"output_format_{role}_{mode}"

    # Delete the override if it exists
    setting = db.query(GlobalSetting).filter(GlobalSetting.key == key).first()
    if setting:
        db.delete(setting)
        db.commit()

    invalidate_template_cache()

    return {"key": key, "status": "reset to default"}


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
async def mr_review_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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
    from datetime import datetime
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
        mr_review.diff_reviewed_at = datetime.now().astimezone()
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
async def mr_reviews_list_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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
async def watchers_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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
        watcher.last_check = datetime.now().astimezone()
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
        watcher.last_check = datetime.now().astimezone()
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


# ============================================================================
# ============================================================================
# Agent Sessions Page - View agent execution logs
# ============================================================================

@router.get("/agent-sessions", response_class=HTMLResponse)
async def agent_sessions_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Page to view all agent sessions"""
    from app.models.scanner_models import AgentSession

    sessions = db.query(AgentSession).order_by(AgentSession.created_at.desc()).limit(100).all()

    return templates.TemplateResponse("agent_sessions.html", {
        "request": request,
        "sessions": sessions,
    })


@router.get("/agent-sessions/{session_id}")
async def get_agent_session(session_id: int, db: Session = Depends(get_db)):
    """Get a single agent session with full trace"""
    from app.models.scanner_models import AgentSession

    session = db.query(AgentSession).filter(AgentSession.id == session_id).first()
    if not session:
        return JSONResponse({"error": "Session not found"}, status_code=404)

    return JSONResponse({
        "id": session.id,
        "scan_id": session.scan_id,
        "finding_id": session.finding_id,
        "draft_finding_id": session.draft_finding_id,
        "status": session.status,
        "model_name": session.model_name,
        "verdict": session.verdict,
        "confidence": session.confidence,
        "reasoning": session.reasoning,
        "attack_path": session.attack_path,
        "total_steps": session.total_steps,
        "max_steps": session.max_steps,
        "total_tokens": session.total_tokens,
        "duration_ms": session.duration_ms,
        "execution_trace": session.execution_trace,
        "task_prompt": session.task_prompt,
        "prefetched_context": session.prefetched_context,
        "error_message": session.error_message,
        "created_at": session.created_at.isoformat() if session.created_at else None,
        "completed_at": session.completed_at.isoformat() if session.completed_at else None,
    })


@router.delete("/agent-sessions/{session_id}")
async def delete_agent_session(session_id: int, db: Session = Depends(get_db)):
    """Delete an agent session"""
    from app.models.scanner_models import AgentSession

    session = db.query(AgentSession).filter(AgentSession.id == session_id).first()
    if not session:
        return JSONResponse({"error": "Session not found"}, status_code=404)

    db.delete(session)
    db.commit()
    return JSONResponse({"success": True})


@router.delete("/agent-sessions")
async def cleanup_agent_sessions(older_than_days: int = 7, db: Session = Depends(get_db)):
    """Delete agent sessions older than N days"""
    from app.models.scanner_models import AgentSession
    from datetime import datetime, timedelta

    cutoff = datetime.now() - timedelta(days=older_than_days)
    deleted = db.query(AgentSession).filter(AgentSession.created_at < cutoff).delete()
    db.commit()

    return JSONResponse({"success": True, "deleted": deleted})


# ============================================================================
# ============================================================================
# Tuning Page - Testing and debugging
# ============================================================================

@router.get("/tuning", response_class=HTMLResponse)
async def tuning_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Tuning page for testing output formats and viewing LLM logs"""
    return templates.TemplateResponse("tuning.html", {
        "request": request,
    })


@router.post("/tuning/test-format")
async def test_output_format(request: Request, db: Session = Depends(get_db)):
    """Test a specific model with a given output format and code sample"""
    import time
    from app.services.analysis.output_formats import get_output_format
    from app.services.analysis.parsers import DraftParser
    from app.services.llm_provider import llm_provider

    try:
        data = await request.json()
        model_id = data.get('model_id')
        role = data.get('role', 'analyzer')
        output_mode = data.get('output_mode', 'markers')
        code = data.get('code', '')
        language = data.get('language', 'c')

        if not model_id or not code:
            return JSONResponse({"error": "model_id and code are required"}, status_code=400)

        # Get model config
        model_config = db.query(ModelConfig).filter(ModelConfig.id == int(model_id)).first()
        if not model_config:
            return JSONResponse({"error": "Model not found"}, status_code=404)

        # Build test prompt
        output_format = get_output_format(role, output_mode)

        # Format code with line numbers
        lines = code.split('\n')
        formatted_code = '\n'.join(f"{i+1:4d} | {line}" for i, line in enumerate(lines))

        test_prompt = f"""Analyze this {language} code for security vulnerabilities.

=== CODE TO ANALYZE ===
{formatted_code}

{output_format}"""

        # Call LLM
        start_time = time.time()

        # Build JSON schema if using guided_json
        json_schema = None
        if output_mode == "guided_json":
            json_schema = {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "vulnerability_type": {"type": "string"},
                                "severity": {"type": "string"},
                                "line_number": {"type": "integer"},
                                "snippet": {"type": "string"},
                                "reason": {"type": "string"}
                            },
                            "required": ["title", "vulnerability_type", "severity", "line_number"]
                        }
                    }
                },
                "required": ["findings"]
            }

        result = await llm_provider.chat_completion(
            messages=[{"role": "user", "content": test_prompt}],
            model=model_config.name,
            max_tokens=2000,
            json_schema=json_schema if output_mode == "guided_json" else None
        )

        duration_ms = int((time.time() - start_time) * 1000)
        raw_response = result.get("content", "")

        # Try to parse the response
        parser = DraftParser()
        parsed_findings = parser.parse(raw_response)

        return {
            "model": model_config.name,
            "output_mode": output_mode,
            "raw_response": raw_response,
            "parse_success": parsed_findings is not None,
            "parsed_findings": parsed_findings,
            "findings_count": len(parsed_findings) if parsed_findings else 0,
            "duration_ms": duration_ms
        }

    except Exception as e:
        import traceback
        return JSONResponse({
            "error": str(e),
            "traceback": traceback.format_exc(),
            "parse_success": False
        }, status_code=500)


# LLM Request Logs - Debugging endpoints (also accessible via /tuning page)
# ============================================================================

@router.get("/llm-logs", response_class=HTMLResponse)
async def llm_logs_page(request: Request, db: Session = Depends(get_db)):
    """LLM request logs page for debugging parsing issues"""
    return templates.TemplateResponse("llm_logs.html", {
        "request": request,
    })


@router.get("/llm-logs/list")
async def get_llm_logs(
    scan_id: Optional[int] = None,
    phase: Optional[str] = None,
    model: Optional[str] = None,
    parse_success: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Get LLM request logs with optional filtering"""
    query = db.query(LLMRequestLog).order_by(LLMRequestLog.created_at.desc())

    if scan_id is not None:
        query = query.filter(LLMRequestLog.scan_id == scan_id)
    if phase:
        query = query.filter(LLMRequestLog.phase == phase)
    if model:
        query = query.filter(LLMRequestLog.model_name == model)
    if parse_success is not None:
        query = query.filter(LLMRequestLog.parse_success == parse_success)

    total = query.count()
    logs = query.offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "logs": [
            {
                "id": log.id,
                "scan_id": log.scan_id,
                "model_name": log.model_name,
                "phase": log.phase,
                "analyzer_name": log.analyzer_name,
                "file_path": log.file_path,
                "chunk_id": log.chunk_id,
                "parse_success": log.parse_success,
                "parse_error": log.parse_error,
                "findings_count": log.findings_count,
                "tokens_in": log.tokens_in,
                "tokens_out": log.tokens_out,
                "duration_ms": log.duration_ms,
                "created_at": log.created_at.isoformat() if log.created_at else None,
                # Truncate for list view
                "request_preview": (log.request_prompt[:200] + "...") if log.request_prompt and len(log.request_prompt) > 200 else log.request_prompt,
                "response_preview": (log.raw_response[:200] + "...") if log.raw_response and len(log.raw_response) > 200 else log.raw_response,
            }
            for log in logs
        ]
    }


@router.get("/llm-logs/{log_id}")
async def get_llm_log_detail(log_id: int, db: Session = Depends(get_db)):
    """Get full details of a single LLM request log"""
    log = db.query(LLMRequestLog).filter(LLMRequestLog.id == log_id).first()
    if not log:
        return JSONResponse({"error": "Log not found"}, status_code=404)

    return {
        "id": log.id,
        "scan_id": log.scan_id,
        "mr_review_id": log.mr_review_id,
        "model_name": log.model_name,
        "phase": log.phase,
        "analyzer_name": log.analyzer_name,
        "file_path": log.file_path,
        "chunk_id": log.chunk_id,
        "request_prompt": log.request_prompt,
        "raw_response": log.raw_response,
        "parsed_result": log.parsed_result,
        "parse_success": log.parse_success,
        "parse_error": log.parse_error,
        "findings_count": log.findings_count,
        "tokens_in": log.tokens_in,
        "tokens_out": log.tokens_out,
        "duration_ms": log.duration_ms,
        "created_at": log.created_at.isoformat() if log.created_at else None,
    }


@router.delete("/llm-logs")
async def clear_llm_logs(
    scan_id: Optional[int] = None,
    older_than_days: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Clear LLM logs, optionally filtered by scan_id or age"""
    from datetime import datetime, timedelta

    query = db.query(LLMRequestLog)

    if scan_id is not None:
        query = query.filter(LLMRequestLog.scan_id == scan_id)

    if older_than_days is not None:
        cutoff = datetime.now().astimezone() - timedelta(days=older_than_days)
        query = query.filter(LLMRequestLog.created_at < cutoff)

    count = query.count()
    query.delete()
    db.commit()

    return {"deleted": count}


@router.get("/llm-logs/stats")
async def get_llm_log_stats(db: Session = Depends(get_db)):
    """Get statistics about LLM logs"""
    total = db.query(LLMRequestLog).count()
    failed = db.query(LLMRequestLog).filter(LLMRequestLog.parse_success == False).count()

    # Get counts by phase
    phase_counts = db.query(
        LLMRequestLog.phase,
        func.count(LLMRequestLog.id)
    ).group_by(LLMRequestLog.phase).all()

    # Get counts by model
    model_counts = db.query(
        LLMRequestLog.model_name,
        func.count(LLMRequestLog.id)
    ).group_by(LLMRequestLog.model_name).all()

    # Get recent scans with logs
    recent_scans = db.query(
        LLMRequestLog.scan_id,
        func.count(LLMRequestLog.id).label('log_count')
    ).filter(LLMRequestLog.scan_id.isnot(None)).group_by(
        LLMRequestLog.scan_id
    ).order_by(func.max(LLMRequestLog.created_at).desc()).limit(20).all()

    return {
        "total": total,
        "failed_parses": failed,
        "success_rate": round((total - failed) / total * 100, 1) if total > 0 else 100,
        "by_phase": {phase: count for phase, count in phase_counts},
        "by_model": {model: count for model, count in model_counts},
        "recent_scans": [{"scan_id": s, "log_count": c} for s, c in recent_scans if s],
    }


# =============================================================================
# LLM Queue Monitoring Endpoints
# =============================================================================

@router.get("/queue")
async def get_queue_page(request: Request, db: Session = Depends(get_db)):
    """Queue monitoring dashboard page"""
    # Get all configured models
    models = db.query(ModelConfig).all()

    return templates.TemplateResponse("queue.html", {
        "request": request,
        "models": [{"id": m.id, "name": m.name, "max_concurrent": m.max_concurrent} for m in models],
    })


@router.get("/queue/phase-allocation")
async def get_phase_allocation():
    """Get current phase slot allocation status for all running scans"""
    from app.services.orchestration.queue_manager import phase_allocator

    # Get all registered scans
    results = {}
    for scan_id in list(phase_allocator._allocated.keys()):
        results[scan_id] = phase_allocator.get_allocation_status(scan_id)

    return {
        "scans": results,
        "description": {
            "scanner": "Draft finding identification (70% base)",
            "verifier": "Finding verification (up to 30%)",
            "enricher": "Report generation (up to 10%)"
        }
    }


@router.get("/queue/state")
async def get_queue_state(db: Session = Depends(get_db)):
    """Get current queue state for all models"""
    from datetime import datetime, timedelta

    # Get all models
    models = db.query(ModelConfig).all()

    # Get pending and running requests from LLMRequestLog
    pending = db.query(LLMRequestLog).filter(LLMRequestLog.status == "pending").all()
    running = db.query(LLMRequestLog).filter(LLMRequestLog.status == "running").all()

    # Get recent completed/failed (last 5 minutes)
    cutoff = datetime.now() - timedelta(minutes=5)
    recent = db.query(LLMRequestLog).filter(
        LLMRequestLog.status.in_(["completed", "failed"]),
        LLMRequestLog.created_at >= cutoff
    ).order_by(LLMRequestLog.created_at.desc()).limit(50).all()

    # Group by model
    model_queues = {}
    for model in models:
        model_queues[model.name] = {
            "name": model.name,
            "max_concurrent": model.max_concurrent,
            "queued": [],
            "running": [],
            "recent_completed": [],
            "recent_failed": [],
        }

    # Add pending requests
    for log in pending:
        if log.model_name in model_queues:
            model_queues[log.model_name]["queued"].append({
                "id": log.id,
                "scan_id": log.scan_id,
                "phase": log.phase,
                "analyzer_name": log.analyzer_name,
                "file_path": log.file_path,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            })

    # Add running requests
    for log in running:
        if log.model_name in model_queues:
            model_queues[log.model_name]["running"].append({
                "id": log.id,
                "scan_id": log.scan_id,
                "phase": log.phase,
                "analyzer_name": log.analyzer_name,
                "file_path": log.file_path,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            })

    # Add recent completed/failed
    for log in recent:
        if log.model_name in model_queues:
            entry = {
                "id": log.id,
                "scan_id": log.scan_id,
                "phase": log.phase,
                "analyzer_name": log.analyzer_name,
                "file_path": log.file_path,
                "duration_ms": log.duration_ms,
                "tokens_in": log.tokens_in,
                "tokens_out": log.tokens_out,
                "created_at": log.created_at.isoformat() if log.created_at else None,
                "status": log.status,
            }
            if log.status == "completed":
                model_queues[log.model_name]["recent_completed"].append(entry)
            else:
                model_queues[log.model_name]["recent_failed"].append(entry)

    # Calculate totals
    total_queued = sum(len(q["queued"]) for q in model_queues.values())
    total_running = sum(len(q["running"]) for q in model_queues.values())

    return {
        "timestamp": datetime.now().isoformat(),
        "total_queued": total_queued,
        "total_running": total_running,
        "models": list(model_queues.values()),
    }


@router.post("/queue/clear")
async def clear_queue(db: Session = Depends(get_db)):
    """Clear all stale queued/running requests.

    Use this when the queue shows requests but no scans are actually running.
    Clears both the in-memory queue manager and stale database entries.
    """
    from app.services.orchestration.queue_manager import queue_manager
    from datetime import datetime

    # Clear in-memory queue
    memory_cleared = queue_manager.clear_all()

    # Clear stale database entries (mark as failed with cleanup note)
    stale_pending = db.query(LLMRequestLog).filter(LLMRequestLog.status == "pending").all()
    stale_running = db.query(LLMRequestLog).filter(LLMRequestLog.status == "running").all()

    db_cleared = {
        "pending": len(stale_pending),
        "running": len(stale_running),
    }

    for log in stale_pending + stale_running:
        log.status = "failed"
        log.parse_error = "Cleared by queue cleanup"

    db.commit()

    return {
        "success": True,
        "cleared_at": datetime.now().isoformat(),
        "memory_queue": memory_cleared,
        "database_queue": db_cleared,
        "total_cleared": memory_cleared["queued"] + memory_cleared["running"] + db_cleared["pending"] + db_cleared["running"]
    }


@router.get("/queue/stream")
async def stream_queue_updates(request: Request, db: Session = Depends(get_db)):
    """SSE stream of queue state updates"""
    from starlette.responses import StreamingResponse
    from datetime import datetime, timedelta
    import json as json_module
    import asyncio

    async def generate_events():
        """Generate SSE events for queue updates"""
        last_state = None

        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                break

            try:
                # Get current state (use a fresh session for each query)
                db_local = SessionLocal()
                try:
                    # Auto-expire stale running tasks (older than 20 minutes)
                    expire_cutoff = datetime.now() - timedelta(minutes=20)
                    stale_running = db_local.query(LLMRequestLog).filter(
                        LLMRequestLog.status == "running",
                        LLMRequestLog.created_at < expire_cutoff
                    ).all()
                    for stale in stale_running:
                        stale.status = "failed"
                        stale.parse_error = "Auto-expired after 20 minutes"
                    if stale_running:
                        db_local.commit()

                    models = db_local.query(ModelConfig).all()
                    pending = db_local.query(LLMRequestLog).filter(LLMRequestLog.status == "pending").all()
                    running = db_local.query(LLMRequestLog).filter(LLMRequestLog.status == "running").all()

                    # Get recent completed/failed (last 1 minute for streaming)
                    cutoff = datetime.now() - timedelta(minutes=1)
                    recent = db_local.query(LLMRequestLog).filter(
                        LLMRequestLog.status.in_(["completed", "failed"]),
                        LLMRequestLog.created_at >= cutoff
                    ).order_by(LLMRequestLog.created_at.desc()).limit(20).all()

                    # Build state
                    model_queues = {}
                    for model in models:
                        model_queues[model.name] = {
                            "name": model.name,
                            "max_concurrent": model.max_concurrent,
                            "queued_count": 0,
                            "running_count": 0,
                            "queued": [],
                            "running": [],
                            "recent": [],
                        }

                    for log in pending:
                        if log.model_name in model_queues:
                            model_queues[log.model_name]["queued_count"] += 1
                            model_queues[log.model_name]["queued"].append({
                                "id": log.id,
                                "scan_id": log.scan_id,
                                "phase": log.phase,
                                "analyzer_name": log.analyzer_name,
                                "file_path": os.path.basename(log.file_path) if log.file_path else None,
                                "created_at": log.created_at.isoformat() if log.created_at else None,
                            })

                    for log in running:
                        if log.model_name in model_queues:
                            model_queues[log.model_name]["running_count"] += 1
                            model_queues[log.model_name]["running"].append({
                                "id": log.id,
                                "scan_id": log.scan_id,
                                "phase": log.phase,
                                "analyzer_name": log.analyzer_name,
                                "file_path": os.path.basename(log.file_path) if log.file_path else None,
                                "created_at": log.created_at.isoformat() if log.created_at else None,
                            })

                    for log in recent:
                        if log.model_name in model_queues:
                            model_queues[log.model_name]["recent"].append({
                                "id": log.id,
                                "scan_id": log.scan_id,
                                "phase": log.phase,
                                "status": log.status,
                                "duration_ms": log.duration_ms,
                                "tokens_out": log.tokens_out,
                            })

                    state = {
                        "timestamp": datetime.now().isoformat(),
                        "total_queued": len(pending),
                        "total_running": len(running),
                        "models": list(model_queues.values()),
                    }

                    # Only send if state changed
                    state_json = json_module.dumps(state)
                    if state_json != last_state:
                        last_state = state_json
                        yield f"data: {state_json}\n\n"

                finally:
                    db_local.close()

            except Exception as e:
                yield f"data: {json_module.dumps({'error': str(e)})}\n\n"

            # Poll every 500ms
            await asyncio.sleep(0.5)

    return StreamingResponse(generate_events(), media_type="text/event-stream")


# =============================================================================
# Model Discovery Endpoint
# =============================================================================

@router.post("/models/discover")
async def discover_models(request: Request, db: Session = Depends(get_db)):
    """
    Discover models from the default LLM API endpoint.
    Tests each model for JSON mode and tool calling support.
    """
    import httpx
    import asyncio

    # Get default settings
    base_url = None
    api_key = None

    # Try to get from global settings first
    base_url_setting = db.query(GlobalSetting).filter(GlobalSetting.key == "llm_base_url").first()
    api_key_setting = db.query(GlobalSetting).filter(GlobalSetting.key == "llm_api_key").first()

    if base_url_setting:
        base_url = base_url_setting.value
    if api_key_setting:
        api_key = api_key_setting.value

    # Fall back to config settings
    if not base_url:
        from app.core.config import settings as app_settings
        base_url = app_settings.LLM_BASE_URL
        api_key = api_key or app_settings.LLM_API_KEY

    if not base_url:
        return JSONResponse({"error": "No LLM base URL configured. Set it in Connection settings first."}, status_code=400)

    # Normalize base URL
    base = base_url.rstrip('/')
    if not base.endswith('/v1'):
        base = f"{base}/v1"

    discovered = []
    errors = []

    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        # Fetch available models
        try:
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            response = await client.get(f"{base}/models", headers=headers)

            if response.status_code != 200:
                return JSONResponse({
                    "error": f"Failed to fetch models: HTTP {response.status_code}",
                    "detail": response.text[:500]
                }, status_code=400)

            data = response.json()
            models_data = data.get("data", [])

            if not models_data:
                return JSONResponse({"error": "No models found at endpoint", "models": []}, status_code=200)

        except Exception as e:
            return JSONResponse({"error": f"Failed to connect to LLM API: {str(e)}"}, status_code=400)

        # Known tool calling formats by model family
        def get_expected_tool_format(model_name: str) -> str:
            """Determine expected tool calling format based on model name."""
            name_lower = model_name.lower()

            # Hermes models use Hermes format
            if "hermes" in name_lower:
                return "hermes"

            # Mistral/Mixtral models - native tool support
            if "mistral" in name_lower or "mixtral" in name_lower:
                return "openai"

            # Llama 3.1+ and 3.2+ have native tool support
            if "llama-3.1" in name_lower or "llama-3.2" in name_lower or "llama3.1" in name_lower or "llama3.2" in name_lower:
                return "openai"

            # Qwen 2.5 has tool support
            if "qwen2.5" in name_lower or "qwen-2.5" in name_lower:
                return "openai"

            # DeepSeek models
            if "deepseek" in name_lower:
                return "openai"

            # Command-R models
            if "command-r" in name_lower or "command_r" in name_lower:
                return "openai"

            # Functionary models are specifically for function calling
            if "functionary" in name_lower:
                return "openai"

            # Default - no known format
            return "none"

        # Test each model
        async def test_model(model_info):
            model_id = model_info.get("id", "")
            # Extract max_model_len from vLLM response (context window size)
            max_context = model_info.get("max_model_len", 0) or model_info.get("context_length", 0) or 0
            result = {
                "name": model_id,
                "base_url": "",  # Use default
                "max_tokens": 4096,
                "max_context_length": max_context,
                "max_concurrent": 2,
                "response_format": "markers",
                "tool_call_format": "none",
                "supports_json": False,
                "supports_guided_json": False,
                "supports_tools": False,
                "test_passed": False,
                "error": None,
                "expected_tool_format": get_expected_tool_format(model_id)
            }

            # Skip embedding models
            if "embed" in model_id.lower():
                result["error"] = "Embedding model (skipped)"
                return result

            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

            # Test 1: Basic completion
            try:
                basic_response = await client.post(
                    f"{base}/chat/completions",
                    headers=headers,
                    json={
                        "model": model_id,
                        "messages": [{"role": "user", "content": "Say 'test' and nothing else."}],
                        "max_tokens": 10,
                        "temperature": 0
                    },
                    timeout=30.0
                )

                if basic_response.status_code != 200:
                    result["error"] = f"Basic test failed: HTTP {basic_response.status_code}"
                    return result

                result["test_passed"] = True

            except Exception as e:
                result["error"] = f"Basic test failed: {str(e)}"
                return result

            # Test 2a: vLLM guided_json (preferred)
            test_schema = {
                "type": "object",
                "properties": {
                    "status": {"type": "string"}
                },
                "required": ["status"]
            }

            try:
                guided_response = await client.post(
                    f"{base}/chat/completions",
                    headers=headers,
                    json={
                        "model": model_id,
                        "messages": [{"role": "user", "content": "Return JSON with status set to ok."}],
                        "max_tokens": 50,
                        "temperature": 0,
                        "guided_json": test_schema
                    },
                    timeout=30.0
                )

                if guided_response.status_code == 200:
                    # Validate the response is actually valid JSON with the required field
                    try:
                        resp_data = guided_response.json()
                        content = resp_data.get("choices", [{}])[0].get("message", {}).get("content", "")
                        parsed = json.loads(content)
                        # Check if response matches schema (has 'status' key)
                        if isinstance(parsed, dict) and "status" in parsed:
                            result["supports_guided_json"] = True
                            result["supports_json"] = True
                            result["response_format"] = "guided_json"
                    except (json.JSONDecodeError, KeyError, IndexError):
                        pass  # Response wasn't valid JSON - guided_json not working

            except Exception:
                pass

            # Test 2b: OpenAI JSON mode (fallback)
            if not result["supports_guided_json"]:
                try:
                    json_response = await client.post(
                        f"{base}/chat/completions",
                        headers=headers,
                        json={
                            "model": model_id,
                            "messages": [{"role": "user", "content": "Return a JSON object with key 'status' and value 'ok'."}],
                            "max_tokens": 50,
                            "temperature": 0,
                            "response_format": {"type": "json_object"}
                        },
                        timeout=30.0
                    )

                    if json_response.status_code == 200:
                        # Validate the response is actually valid JSON
                        try:
                            resp_data = json_response.json()
                            content = resp_data.get("choices", [{}])[0].get("message", {}).get("content", "")
                            parsed = json.loads(content)
                            if isinstance(parsed, dict):
                                result["supports_json"] = True
                                result["response_format"] = "json"
                        except (json.JSONDecodeError, KeyError, IndexError):
                            pass  # Response wasn't valid JSON

                except Exception:
                    pass

            # Test 3: Tool calling (OpenAI format - used by vLLM)
            try:
                tools_response = await client.post(
                    f"{base}/chat/completions",
                    headers=headers,
                    json={
                        "model": model_id,
                        "messages": [{"role": "user", "content": "What is 2+2? Use the calculate tool."}],
                        "max_tokens": 100,
                        "temperature": 0,
                        "tools": [{
                            "type": "function",
                            "function": {
                                "name": "calculate",
                                "description": "Perform a calculation",
                                "parameters": {
                                    "type": "object",
                                    "properties": {
                                        "expression": {"type": "string", "description": "Math expression"}
                                    },
                                    "required": ["expression"]
                                }
                            }
                        }],
                        "tool_choice": "auto"
                    },
                    timeout=30.0
                )

                if tools_response.status_code == 200:
                    resp_data = tools_response.json()
                    choices = resp_data.get("choices", [])
                    if choices:
                        message = choices[0].get("message", {})
                        # Check if model used tool calling
                        if message.get("tool_calls"):
                            result["supports_tools"] = True
                            result["tool_call_format"] = "openai"
                        else:
                            # API accepted tools param - check if model family supports it
                            expected = result["expected_tool_format"]
                            if expected != "none":
                                result["supports_tools"] = True
                                result["tool_call_format"] = expected

            except Exception:
                pass

            # If no tool test passed but we know the model family supports tools, set it
            if not result["supports_tools"] and result["expected_tool_format"] != "none":
                result["tool_call_format"] = result["expected_tool_format"]
                result["supports_tools"] = True  # Assume support based on model family

            return result

        # Test all models concurrently (with limit)
        semaphore = asyncio.Semaphore(3)  # Max 3 concurrent tests

        async def test_with_semaphore(model_info):
            async with semaphore:
                return await test_model(model_info)

        tasks = [test_with_semaphore(m) for m in models_data]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                errors.append(str(r))
            elif isinstance(r, dict):
                discovered.append(r)

    # Check which models already exist
    existing_names = {m.name for m in db.query(ModelConfig.name).all()}

    for model in discovered:
        model["already_exists"] = model["name"] in existing_names

    return {
        "discovered": discovered,
        "total": len(discovered),
        "new": len([m for m in discovered if not m.get("already_exists")]),
        "errors": errors
    }


@router.post("/models/import")
async def import_discovered_models(request: Request, db: Session = Depends(get_db)):
    """Import discovered models into the database"""
    data = await request.json()
    models_to_import = data.get("models", [])
    update_existing = data.get("update_existing", False)

    imported = []
    updated = []
    skipped = []

    for model_data in models_to_import:
        name = model_data.get("name")
        if not name:
            continue

        # Check if already exists
        existing = db.query(ModelConfig).filter(ModelConfig.name == name).first()
        if existing:
            if update_existing:
                # Update existing model with discovered capabilities
                if model_data.get("response_format"):
                    existing.response_format = model_data["response_format"]
                if model_data.get("tool_call_format"):
                    existing.tool_call_format = model_data["tool_call_format"]
                if model_data.get("max_context_length"):
                    existing.max_context_length = model_data["max_context_length"]
                updated.append(name)
            else:
                skipped.append(name)
            continue

        model = ModelConfig(
            name=name,
            base_url=model_data.get("base_url", ""),
            api_key=model_data.get("api_key", ""),
            max_tokens=model_data.get("max_tokens", 4096),
            max_context_length=model_data.get("max_context_length", 0),
            max_concurrent=model_data.get("max_concurrent", 2),
            votes=model_data.get("votes", 1),
            chunk_size=model_data.get("chunk_size", 3000),
            response_format=model_data.get("response_format", "markers"),
            tool_call_format=model_data.get("tool_call_format", "none"),
            is_chat=model_data.get("is_chat", False),
        )
        db.add(model)
        imported.append(name)

    db.commit()

    return {
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "total_imported": len(imported),
        "total_updated": len(updated)
    }


@router.post("/models/sync-context-length")
async def sync_model_context_lengths(db: Session = Depends(get_db)):
    """
    Sync max_context_length for all existing models from the v1/models endpoint.
    Fetches model info and updates the max_context_length for matching models.
    """
    import httpx

    # Get default settings
    base_url = None
    api_key = None

    # Try to get from global settings first
    base_url_setting = db.query(GlobalSetting).filter(GlobalSetting.key == "llm_base_url").first()
    api_key_setting = db.query(GlobalSetting).filter(GlobalSetting.key == "llm_api_key").first()

    if base_url_setting:
        base_url = base_url_setting.value
    if api_key_setting:
        api_key = api_key_setting.value

    # Fall back to config settings
    if not base_url:
        from app.core.config import settings as app_settings
        base_url = app_settings.LLM_BASE_URL
        api_key = api_key or app_settings.LLM_API_KEY

    if not base_url:
        return JSONResponse({"error": "No LLM base URL configured"}, status_code=400)

    # Normalize base URL
    base = base_url.rstrip('/')
    if not base.endswith('/v1'):
        base = f"{base}/v1"

    updated = []
    not_found = []
    errors = []

    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        # Fetch available models
        try:
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            response = await client.get(f"{base}/models", headers=headers)

            if response.status_code != 200:
                return JSONResponse({
                    "error": f"Failed to fetch models: HTTP {response.status_code}",
                    "detail": response.text[:500]
                }, status_code=400)

            data = response.json()
            models_data = data.get("data", [])

            # Build lookup by model ID
            api_models = {}
            for m in models_data:
                model_id = m.get("id", "")
                max_context = m.get("max_model_len", 0) or m.get("context_length", 0) or 0
                api_models[model_id] = max_context

        except Exception as e:
            return JSONResponse({"error": f"Failed to connect to LLM API: {str(e)}"}, status_code=400)

    # Update all existing models
    db_models = db.query(ModelConfig).all()
    for model in db_models:
        if model.name in api_models:
            new_context = api_models[model.name]
            if new_context > 0:
                model.max_context_length = new_context
                updated.append({"name": model.name, "max_context_length": new_context})
        else:
            not_found.append(model.name)

    db.commit()

    return {
        "updated": updated,
        "not_found": not_found,
        "total_updated": len(updated)
    }


@router.post("/profiles/create-full")
async def create_full_scan_profile(request: Request, db: Session = Depends(get_db)):
    """
    Create a comprehensive scan profile with:
    - An analyzer for each model
    - A verifier for each model
    - Agent verification enabled for tool-calling models
    """
    from app.models.scanner_models import ScanProfile, ProfileAnalyzer, ProfileVerifier

    # Get all models
    models = db.query(ModelConfig).all()
    if not models:
        return JSONResponse({"error": "No models configured. Add models first."}, status_code=400)

    # Create the profile
    profile = ScanProfile(
        name="Full Multi-Model Scan",
        description="Comprehensive scan using all available models as analyzers and verifiers",
        is_active=True,
        verification_threshold=2,
        enrichment_model_id=models[0].id if models else None,
        use_agent_verification=True
    )
    db.add(profile)
    db.flush()  # Get the profile ID

    # Default analyzer prompt
    analyzer_prompt = """Analyze the following {language} code for security vulnerabilities.

Focus on:
- Input validation issues (SQL injection, command injection, XSS, path traversal)
- Memory safety issues (buffer overflow, use-after-free, null pointer dereference)
- Authentication/authorization flaws
- Cryptographic weaknesses
- Resource leaks and denial of service vectors

Code to analyze:
```{language}
{code}
```

{output_format}"""

    # Default verifier prompt
    verifier_prompt = """You are a security expert verifying a potential vulnerability finding.

## Reported Vulnerability
**Type:** {vulnerability_type}
**Severity:** {severity}
**Title:** {title}

## Code Context
```
{code_context}
```

## Finding Details
{details}

Evaluate if this is a real, exploitable security vulnerability. Consider:
1. Can an attacker actually trigger this code path?
2. Is user input involved that could be malicious?
3. Are there existing mitigations or sanitization?
4. What is the realistic impact if exploited?

{output_format}"""

    analyzers_created = 0
    verifiers_created = 0
    agents_enabled = 0

    # Create an analyzer and verifier for each model
    for idx, model in enumerate(models):
        # Create analyzer
        analyzer = ProfileAnalyzer(
            profile_id=profile.id,
            name=f"{model.name} Analyzer",
            model_id=model.id,
            prompt_template=analyzer_prompt,
            chunk_size=6000,
            file_filter="*.py,*.c,*.cpp,*.h,*.hpp,*.js,*.ts,*.java,*.go,*.rs",
            run_order=idx + 1,
            role="analyzer",
            enabled=True
        )
        db.add(analyzer)
        analyzers_created += 1

        # Create verifier
        verifier = ProfileVerifier(
            profile_id=profile.id,
            name=f"{model.name} Verifier",
            model_id=model.id,
            prompt_template=verifier_prompt,
            vote_weight=1.0,
            min_confidence=0,
            run_order=idx + 1,
            enabled=True
        )
        db.add(verifier)
        verifiers_created += 1

        # Track if model supports tool calling (for agent verification)
        if model.tool_call_format and model.tool_call_format != "none":
            agents_enabled += 1

    db.commit()

    return {
        "success": True,
        "profile_id": profile.id,
        "profile_name": profile.name,
        "analyzers_created": analyzers_created,
        "verifiers_created": verifiers_created,
        "models_with_agent_support": agents_enabled,
        "message": f"Created profile with {analyzers_created} analyzers and {verifiers_created} verifiers. {agents_enabled} models support agent verification."
    }
