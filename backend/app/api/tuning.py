"""
API endpoints for prompt tuning system.

This is a standalone utility for testing verification prompts against ground truth.
Bypasses all scanning queues - makes direct API calls to LLMs.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import asyncio
import json

from app.core.database import get_db
from app.models.tuning_models import TuningPromptTemplate, TuningTestCase, TuningRun, TuningResult
from app.models.scanner_models import ModelConfig
from app.services.tuning.prompt_tuner import PromptTuner
from app.services.tuning.run_controller import TuningRunController

router = APIRouter()


# ============================================================================
# Request/Response Models
# ============================================================================

class PromptTemplateCreate(BaseModel):
    name: str
    description: Optional[str] = None
    template: str


class PromptTemplateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    template: Optional[str] = None


class TestCaseCreate(BaseModel):
    name: str
    verdict: str
    issue: str
    file: str
    code: str
    claim: str


class TestCaseUpdate(BaseModel):
    name: Optional[str] = None
    verdict: Optional[str] = None
    issue: Optional[str] = None
    file: Optional[str] = None
    code: Optional[str] = None
    claim: Optional[str] = None


class TuningRunRequest(BaseModel):
    model_ids: List[int]
    prompt_ids: List[int]
    test_case_ids: List[int]
    concurrency: int = 4
    name: Optional[str] = None
    description: Optional[str] = None


# ============================================================================
# Prompt Template Endpoints
# ============================================================================

@router.get("/prompts")
def get_prompts(db: Session = Depends(get_db)):
    """List all prompt templates"""
    # Sort by ID to keep v1-v26 order correct (lexicographical sort on name puts v10 before v2)
    prompts = db.query(TuningPromptTemplate).order_by(TuningPromptTemplate.id).all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "template": p.template,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        }
        for p in prompts
    ]


@router.get("/prompt-templates/simple")
def get_prompt_templates_simple(db: Session = Depends(get_db)):
    """Get list of prompt templates for selector (simplified)"""
    # Sort by ID for logical ordering
    templates = db.query(TuningPromptTemplate).order_by(TuningPromptTemplate.id).all()
    return [
        {"id": t.id, "name": t.name, "template": t.template}
        for t in templates
    ]


@router.post("/prompts")
def create_prompt(request: PromptTemplateCreate, db: Session = Depends(get_db)):
    """Create a new prompt template"""
    # Check for duplicate name
    existing = db.query(TuningPromptTemplate).filter(
        TuningPromptTemplate.name == request.name
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Prompt with this name already exists")

    prompt = TuningPromptTemplate(
        name=request.name,
        description=request.description,
        template=request.template,
    )
    db.add(prompt)
    db.commit()
    db.refresh(prompt)
    return {"id": prompt.id, "name": prompt.name}


@router.put("/prompts/{prompt_id}")
def update_prompt(prompt_id: int, request: PromptTemplateUpdate, db: Session = Depends(get_db)):
    """Update an existing prompt template"""
    prompt = db.query(TuningPromptTemplate).filter(TuningPromptTemplate.id == prompt_id).first()
    if not prompt:
        raise HTTPException(status_code=404, detail="Prompt not found")

    if request.name is not None:
        # Check for duplicate name
        existing = db.query(TuningPromptTemplate).filter(
            TuningPromptTemplate.name == request.name,
            TuningPromptTemplate.id != prompt_id
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="Prompt with this name already exists")
        prompt.name = request.name

    if request.description is not None:
        prompt.description = request.description
    if request.template is not None:
        prompt.template = request.template

    db.commit()
    return {"id": prompt.id, "name": prompt.name}


@router.delete("/prompts/{prompt_id}")
def delete_prompt(prompt_id: int, db: Session = Depends(get_db)):
    """Delete a prompt template"""
    prompt = db.query(TuningPromptTemplate).filter(TuningPromptTemplate.id == prompt_id).first()
    if not prompt:
        raise HTTPException(status_code=404, detail="Prompt not found")

    db.delete(prompt)
    db.commit()
    return {"success": True}


# ============================================================================
# Test Case Endpoints
# ============================================================================

@router.get("/test-cases")
def get_test_cases(db: Session = Depends(get_db)):
    """List all test cases"""
    cases = db.query(TuningTestCase).order_by(TuningTestCase.name).all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "verdict": c.verdict,
            "issue": c.issue,
            "file": c.file,
            "code": c.code,
            "claim": c.claim,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in cases
    ]


@router.post("/test-cases")
def create_test_case(request: TestCaseCreate, db: Session = Depends(get_db)):
    """Create a new test case"""
    # Check for duplicate name
    existing = db.query(TuningTestCase).filter(TuningTestCase.name == request.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Test case with this name already exists")

    test_case = TuningTestCase(
        name=request.name,
        verdict=request.verdict,
        issue=request.issue,
        file=request.file,
        code=request.code,
        claim=request.claim,
    )
    db.add(test_case)
    db.commit()
    db.refresh(test_case)
    return {"id": test_case.id, "name": test_case.name}


@router.put("/test-cases/{case_id}")
def update_test_case(case_id: int, request: TestCaseUpdate, db: Session = Depends(get_db)):
    """Update an existing test case"""
    test_case = db.query(TuningTestCase).filter(TuningTestCase.id == case_id).first()
    if not test_case:
        raise HTTPException(status_code=404, detail="Test case not found")

    if request.name is not None:
        # Check for duplicate name
        existing = db.query(TuningTestCase).filter(
            TuningTestCase.name == request.name,
            TuningTestCase.id != case_id
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="Test case with this name already exists")
        test_case.name = request.name

    if request.verdict is not None:
        test_case.verdict = request.verdict
    if request.issue is not None:
        test_case.issue = request.issue
    if request.file is not None:
        test_case.file = request.file
    if request.code is not None:
        test_case.code = request.code
    if request.claim is not None:
        test_case.claim = request.claim

    db.commit()
    return {"id": test_case.id, "name": test_case.name}


@router.delete("/test-cases/{case_id}")
def delete_test_case(case_id: int, db: Session = Depends(get_db)):
    """Delete a test case"""
    test_case = db.query(TuningTestCase).filter(TuningTestCase.id == case_id).first()
    if not test_case:
        raise HTTPException(status_code=404, detail="Test case not found")

    db.delete(test_case)
    db.commit()
    return {"success": True}


@router.get("/draft-findings")
def get_draft_findings(
    scan_id: Optional[int] = None,
    finding_id: Optional[int] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """List recent draft findings for importing as test cases"""
    from app.models.scanner_models import DraftFinding
    from app.models.models import Scan
    
    query = db.query(DraftFinding)
    
    if finding_id:
        query = query.filter(DraftFinding.id == finding_id)
    
    if scan_id:
        query = query.filter(DraftFinding.scan_id == scan_id)
        
    # Order by newest first
    drafts = query.order_by(DraftFinding.created_at.desc()).offset(offset).limit(limit).all()
    
    results = []
    for d in drafts:
        # Get vote breakdown
        votes = d.votes  # Relationship
        verify = sum(1 for v in votes if v.decision and v.decision.upper() in ['VERIFY', 'REAL'])
        reject = sum(1 for v in votes if v.decision and v.decision.upper() in ['REJECT', 'FALSE_POSITIVE'])
        weakness = sum(1 for v in votes if v.decision and v.decision.upper() in ['WEAKNESS'])
        
        results.append({
            "id": d.id,
            "scan_id": d.scan_id,
            "title": d.title,
            "severity": d.severity,
            "file_path": d.file_path,
            "line_number": d.line_number,
            "vulnerability_type": d.vulnerability_type,
            "snippet": d.snippet[:200] if d.snippet else None,
            "created_at": d.created_at.isoformat() if d.created_at else None,
            "status": d.status,
            "vote_summary": {
                "verify": verify,
                "reject": reject,
                "weakness": weakness,
                "total": len(votes)
            }
        })
        
    return results


@router.post("/test-cases/from-finding/{finding_id}")
def create_test_case_from_finding(
    finding_id: int,
    verdict: str,
    db: Session = Depends(get_db)
):
    """
    Create a tuning test case from a finding.

    Instead of copying data, stores a reference to the draft_finding_id.
    Test case data is pulled at runtime from the draft finding.

    Args:
        finding_id: The finding to reference
        verdict: Ground truth verdict (REAL, FALSE_POSITIVE, WEAKNESS, NEEDS_VERIFIED)
    """
    from app.models.models import Finding
    from app.models.scanner_models import DraftFinding

    # Get the finding
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get the draft finding - required for this to work
    if not finding.draft_id:
        raise HTTPException(status_code=400, detail="Finding does not have a draft_finding_id - cannot create test case")

    draft = db.query(DraftFinding).filter(DraftFinding.id == finding.draft_id).first()
    if not draft:
        raise HTTPException(status_code=404, detail="Draft finding not found")

    # Create a unique name
    base_name = f"finding_{finding.id}_{finding.title[:30]}"
    name = base_name.replace(" ", "_").replace("/", "_").replace("\\", "_")

    # Check if already exists
    counter = 1
    final_name = name
    while db.query(TuningTestCase).filter(TuningTestCase.name == final_name).first():
        final_name = f"{name}_{counter}"
        counter += 1

    # Create test case with just draft_finding_id reference
    # Data fields are left NULL and will be pulled from draft_finding at runtime
    test_case = TuningTestCase(
        name=final_name,
        verdict=verdict,
        draft_finding_id=finding.draft_id,
        # Leave code, claim, issue, file as NULL - they'll be pulled from draft_finding
    )

    db.add(test_case)
    db.commit()
    db.refresh(test_case)

    return {
        "success": True,
        "test_case_id": test_case.id,
        "name": test_case.name,
        "draft_finding_id": test_case.draft_finding_id,
        "message": "Test case created from finding (referenced, not copied)"
    }


# ============================================================================
# Tuning Run Endpoints
# ============================================================================

@router.get("/runs")
def get_runs(db: Session = Depends(get_db)):
    """List all tuning runs"""
    runs = db.query(TuningRun).order_by(TuningRun.created_at.desc()).limit(50).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "status": r.status,
            "total_tests": r.total_tests,
            "completed_tests": r.completed_tests,
            "total_duration_ms": r.total_duration_ms,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "error_message": r.error_message,
        }
        for r in runs
    ]


@router.post("/run")
async def start_tuning_run(
    request: TuningRunRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Start a new tuning run"""
    # Validate inputs
    if not request.model_ids:
        raise HTTPException(status_code=400, detail="At least one model must be selected")
    if not request.prompt_ids:
        raise HTTPException(status_code=400, detail="At least one prompt must be selected")
    if not request.test_case_ids:
        raise HTTPException(status_code=400, detail="At least one test case must be selected")

    # Verify all models exist and are verifiers
    models = db.query(ModelConfig).filter(ModelConfig.id.in_(request.model_ids)).all()
    if len(models) != len(request.model_ids):
        raise HTTPException(status_code=400, detail="One or more models not found")

    # Verify all prompts exist
    prompts = db.query(TuningPromptTemplate).filter(
        TuningPromptTemplate.id.in_(request.prompt_ids)
    ).all()
    if len(prompts) != len(request.prompt_ids):
        raise HTTPException(status_code=400, detail="One or more prompts not found")

    # Verify all test cases exist
    test_cases = db.query(TuningTestCase).filter(
        TuningTestCase.id.in_(request.test_case_ids)
    ).all()
    if len(test_cases) != len(request.test_case_ids):
        raise HTTPException(status_code=400, detail="One or more test cases not found")

    # Create run record first
    total_tests = len(request.model_ids) * len(request.prompt_ids) * len(request.test_case_ids)
    run = TuningRun(
        name=request.name,
        description=request.description,
        model_ids=request.model_ids,
        prompt_ids=request.prompt_ids,
        test_case_ids=request.test_case_ids,
        concurrency=request.concurrency,
        status="running",
        total_tests=total_tests,
        completed_tests=0,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    run_id = run.id

    # Run tuning in background using the existing run_id
    def run_tuning_task():
        # Create new DB session for background task
        from app.core.database import SessionLocal
        db_task = SessionLocal()
        try:
            tuner = PromptTuner(db_task)
            asyncio.run(tuner.run_tuning_with_existing_run(
                run_id=run_id,
                model_ids=request.model_ids,
                prompt_ids=request.prompt_ids,
                test_case_ids=request.test_case_ids,
                concurrency=request.concurrency,
            ))
        except Exception as e:
            # Update run with error
            run = db_task.query(TuningRun).filter(TuningRun.id == run_id).first()
            if run:
                run.status = "failed"
                run.error_message = str(e)
                db_task.commit()
        finally:
            db_task.close()

    background_tasks.add_task(run_tuning_task)

    return {
        "run_id": run_id,
        "status": "running",
        "total_tests": total_tests,
    }


@router.get("/runs/{run_id}/progress")
def get_run_progress(run_id: int, db: Session = Depends(get_db)):
    """Get progress status for a running tuning run"""
    run = db.query(TuningRun).filter(TuningRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    return {
        "run_id": run.id,
        "status": run.status,
        "total_tests": run.total_tests,
        "completed_tests": run.completed_tests,
        "total_duration_ms": run.total_duration_ms,
    }


@router.get("/runs/{run_id}/results")
def get_run_results(run_id: int, db: Session = Depends(get_db)):
    """Get detailed results and analysis for a run"""
    run = db.query(TuningRun).filter(TuningRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    tuner = PromptTuner(db)
    analysis = tuner.get_run_analysis(run_id)

    # Get individual results
    results = db.query(TuningResult).filter(TuningResult.run_id == run_id).all()
    result_list = [
        {
            "id": r.id,
            "model_name": r.model_name,
            "prompt_id": r.prompt_id,
            "test_case_id": r.test_case_id,
            "predicted_vote": r.predicted_vote,
            "confidence": r.confidence,
            "reasoning": r.reasoning,
            "correct": r.correct,
            "parse_success": r.parse_success,
            "parse_error": r.parse_error,
            "duration_ms": r.duration_ms,
            "raw_response": r.raw_response,
            "full_prompt": r.full_prompt,
        }
        for r in results
    ]

    return {
        "run": {
            "id": run.id,
            "name": run.name,
            "description": run.description,
            "status": run.status,
            "total_tests": run.total_tests,
            "completed_tests": run.completed_tests,
            "total_duration_ms": run.total_duration_ms,
            "created_at": run.created_at.isoformat() if run.created_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        },
        "analysis": analysis,
        "results": result_list,
    }


@router.delete("/runs/{run_id}")
def delete_run(run_id: int, db: Session = Depends(get_db)):
    """Delete a tuning run and all its results"""
    run = db.query(TuningRun).filter(TuningRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    db.delete(run)
    db.commit()
    return {"success": True}


# ============================================================================
# Models Endpoint (for UI dropdown)
# ============================================================================

@router.get("/models")
def get_models(db: Session = Depends(get_db)):
    """Get all models available for benchmarking"""
    models = db.query(ModelConfig).order_by(ModelConfig.name).all()
    return [
        {
            "id": m.id,
            "name": m.name,
        }
        for m in models
    ]


# ============================================================================
# Real-time Streaming and Control Endpoints
# ============================================================================

@router.get("/runs/{run_id}/stream")
async def stream_run_results(
    run_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """SSE stream for real-time benchmark results"""
    controller = TuningRunController.get_instance()

    async def generate_events():
        # Create subscriber queue
        queue = asyncio.Queue(maxsize=100)
        run_state = controller.get_run_state(run_id)

        # Send initial state
        run = db.query(TuningRun).filter(TuningRun.id == run_id).first()
        if not run:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Run not found'})}\n\n"
            return

        if run_state:
            # Run is active - subscribe to updates
            run_state.subscribers.add(queue)

        try:
            # Send connection confirmation with current state
            event_data = {
                'type': 'connected',
                'run': {
                    'id': run.id,
                    'status': run.status,
                    'total_tests': run.total_tests,
                    'completed_tests': run.completed_tests,
                }
            }
            yield f"data: {json.dumps(event_data)}\n\n"

            # Send existing results if reconnecting mid-run
            if run.completed_tests > 0:
                results = db.query(TuningResult).filter(
                    TuningResult.run_id == run_id
                ).order_by(TuningResult.id).limit(run.completed_tests).all()

                for result in results:
                    result_data = {
                        'type': 'existing_result',
                        'data': {
                            'id': result.id,
                            'model_name': result.model_name,
                            'prompt_id': result.prompt_id,
                            'test_case_id': result.test_case_id,
                            'predicted_vote': result.predicted_vote,
                            'confidence': result.confidence,
                            'correct': result.correct,
                            'duration_ms': result.duration_ms,
                        }
                    }
                    yield f"data: {json.dumps(result_data)}\n\n"

            # Stream new events
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    break

                try:
                    # Wait for new event (30s timeout for heartbeat)
                    event = await asyncio.wait_for(queue.get(), timeout=30)

                    # Check for cleanup signal
                    if event.get("type") == "cleanup":
                        break

                    yield f"data: {json.dumps(event)}\n\n"

                except asyncio.TimeoutError:
                    # Send heartbeat to keep connection alive
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

        finally:
            # Unsubscribe
            if run_state:
                run_state.subscribers.discard(queue)

    return StreamingResponse(
        generate_events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


@router.post("/runs/{run_id}/pause")
async def pause_run(run_id: int, db: Session = Depends(get_db)):
    """Pause a running benchmark"""
    controller = TuningRunController.get_instance()
    run = db.query(TuningRun).filter(TuningRun.id == run_id).first()

    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    if run.status != "running":
        raise HTTPException(status_code=400, detail="Can only pause running runs")

    success = await controller.pause_run(run_id)
    if success:
        run.status = "paused"
        run.is_paused = True
        run.pause_requested_at = datetime.now()
        db.commit()

        await controller.broadcast_event(run_id, {
            "type": "paused",
            "message": "Run paused - will complete current test first"
        })

        return {"success": True, "status": "paused"}

    return {"success": False, "message": "Run not active"}


@router.post("/runs/{run_id}/resume")
async def resume_run(run_id: int, db: Session = Depends(get_db)):
    """Resume a paused benchmark"""
    controller = TuningRunController.get_instance()
    run = db.query(TuningRun).filter(TuningRun.id == run_id).first()

    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    if run.status != "paused":
        raise HTTPException(status_code=400, detail="Can only resume paused runs")

    success = await controller.resume_run(run_id)
    if success:
        run.status = "running"
        run.is_paused = False
        run.resumed_at = datetime.now()
        db.commit()

        await controller.broadcast_event(run_id, {
            "type": "resumed",
            "message": "Run resumed"
        })

        return {"success": True, "status": "running"}

    return {"success": False, "message": "Run not active"}


@router.post("/runs/{run_id}/cancel")
async def cancel_run(run_id: int, db: Session = Depends(get_db)):
    """Cancel a running or paused benchmark"""
    controller = TuningRunController.get_instance()
    run = db.query(TuningRun).filter(TuningRun.id == run_id).first()

    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    if run.status not in ["running", "paused"]:
        raise HTTPException(status_code=400, detail="Can only cancel running or paused runs")

    success = await controller.cancel_run(run_id)

    run.status = "cancelled"
    run.completed_at = datetime.now()
    db.commit()

    if success:
        await controller.broadcast_event(run_id, {
            "type": "cancelled",
            "message": "Run cancelled by user"
        })

    return {"success": True, "status": "cancelled"}


@router.get("/results/{result_id}")
def get_result_details(result_id: int, db: Session = Depends(get_db)):
    """Get detailed information for a specific test result"""
    from app.models.scanner_models import DraftFinding

    result = db.query(TuningResult).filter(TuningResult.id == result_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")

    # Get related data
    prompt = db.query(TuningPromptTemplate).filter(
        TuningPromptTemplate.id == result.prompt_id
    ).first()

    test_case = db.query(TuningTestCase).filter(
        TuningTestCase.id == result.test_case_id
    ).first()

    model = db.query(ModelConfig).filter(
        ModelConfig.id == result.model_id
    ).first()

    # If test case references a draft finding, load data from there
    test_case_data = {}
    if test_case:
        if test_case.draft_finding_id:
            draft = db.query(DraftFinding).filter(
                DraftFinding.id == test_case.draft_finding_id
            ).first()
            if draft:
                test_case_data = {
                    "name": test_case.name,
                    "verdict": test_case.verdict,
                    "issue": draft.title,
                    "file": draft.file_path,
                    "code": draft.snippet,
                    "claim": draft.reasoning,
                    "draft_finding_id": test_case.draft_finding_id
                }
        else:
            test_case_data = {
                "name": test_case.name,
                "verdict": test_case.verdict,
                "issue": test_case.issue,
                "file": test_case.file,
                "code": test_case.code,
                "claim": test_case.claim,
            }

    return {
        "id": result.id,
        "run_id": result.run_id,
        "model": {
            "id": model.id if model else None,
            "name": result.model_name,
        },
        "prompt": {
            "id": prompt.id if prompt else None,
            "name": prompt.name if prompt else None,
            "template": prompt.template if prompt else None,
        },
        "test_case": test_case_data,
        "full_prompt": result.full_prompt,
        "raw_response": result.raw_response,
        "predicted_vote": result.predicted_vote,
        "confidence": result.confidence,
        "reasoning": result.reasoning,
        "correct": result.correct,
        "parse_success": result.parse_success,
        "parse_error": result.parse_error,
        "duration_ms": result.duration_ms,
        "tokens_in": result.tokens_in,
        "tokens_out": result.tokens_out,
        "created_at": result.created_at.isoformat() if result.created_at else None,
    }


# ============================================================================
# Bulk Import Endpoints
# ============================================================================

class BulkImportRequest(BaseModel):
    scan_ids: List[int]
    target_count: int = 100
    balance_classes: bool = True
    min_confidence: float = 0.7


@router.post("/test-cases/bulk-import")
def bulk_import_test_cases(
    request: BulkImportRequest,
    db: Session = Depends(get_db)
):
    """
    Bulk import test cases from historical scans.

    Extracts real draft findings with full context (code chunks, verification votes)
    to create realistic test cases that mirror actual scan verification workload.
    """
    from app.services.tuning.test_case_extractor import extract_and_import

    try:
        result = extract_and_import(
            db=db,
            scan_ids=request.scan_ids,
            target_count=request.target_count,
            balance=request.balance_classes,
            min_confidence=request.min_confidence
        )

        return {
            "success": True,
            **result
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/list")
def list_available_scans(db: Session = Depends(get_db)):
    """List all completed scans available for test case extraction"""
    from app.models.models import Scan

    scans = db.query(
        Scan.id,
        Scan.target_url,
        Scan.status,
        Scan.created_at
    ).filter(
        Scan.status.in_(["completed", "paused"])
    ).order_by(
        Scan.id.desc()
    ).limit(50).all()

    return {
        "scans": [
            {
                "id": s.id,
                "name": s.target_url or f"Scan {s.id}",
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None
            }
            for s in scans
        ]
    }


@router.get("/scans/{scan_id}/preview")
def preview_scan_test_cases(
    scan_id: int,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """Preview what test cases would be extracted from a scan"""
    from app.models.scanner_models import DraftFinding

    # Get sample draft findings from this scan
    drafts = db.query(DraftFinding).filter(
        DraftFinding.scan_id == scan_id,
        DraftFinding.status.in_(["verified", "rejected", "weakness"])
    ).limit(limit).all()

    return {
        "scan_id": scan_id,
        "sample_count": len(drafts),
        "samples": [
            {
                "id": d.id,
                "title": d.title,
                "type": d.vulnerability_type,
                "status": d.status,
                "line": d.line_number,
                "file": d.file_path
            }
            for d in drafts
        ]
    }


@router.get("/test-cases/stats")
def get_test_case_stats(db: Session = Depends(get_db)):
    """Get statistics about current test case library"""
    from sqlalchemy import func

    # Total count
    total = db.query(func.count(TuningTestCase.id)).scalar()

    # By verdict
    by_verdict = db.query(
        TuningTestCase.verdict,
        func.count(TuningTestCase.id).label('count')
    ).group_by(TuningTestCase.verdict).all()

    # By CWE type
    by_cwe = db.query(
        TuningTestCase.cwe_type,
        func.count(TuningTestCase.id).label('count')
    ).filter(
        TuningTestCase.cwe_type.isnot(None)
    ).group_by(TuningTestCase.cwe_type).all()

    # By source scan
    by_scan = db.query(
        TuningTestCase.source_scan_id,
        TuningTestCase.source_scan_name,
        func.count(TuningTestCase.id).label('count')
    ).filter(
        TuningTestCase.source_scan_id.isnot(None)
    ).group_by(
        TuningTestCase.source_scan_id,
        TuningTestCase.source_scan_name
    ).all()

    # Synthetic vs real
    synthetic_count = db.query(func.count(TuningTestCase.id)).filter(
        TuningTestCase.is_synthetic == True
    ).scalar()

    real_count = db.query(func.count(TuningTestCase.id)).filter(
        TuningTestCase.is_synthetic == False
    ).scalar()

    return {
        "total": total,
        "by_verdict": {v: c for v, c in by_verdict},
        "by_cwe": {cwe: c for cwe, c in by_cwe},
        "by_scan": [
            {"scan_id": sid, "scan_name": sname, "count": c}
            for sid, sname, c in by_scan
        ],
        "synthetic": synthetic_count,
        "real": real_count
    }
