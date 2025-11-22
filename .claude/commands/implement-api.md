# Implement API Integration

Update the API endpoints to use the new pipeline architecture.

## Task

Update endpoints and add new ones for the refactored scanner.

## Files to Modify/Create

### 1. Update backend/app/api/endpoints.py

#### New Imports
```python
from app.models.scanner_models import (
    ModelConfig, ScanConfig, ScanFile, ScanFileChunk,
    DraftFinding, VerifiedFinding
)
from app.services.orchestration.pipeline import ScanPipeline
from app.services.orchestration.checkpoint import ScanCheckpoint
```

#### Modified /scan/start endpoint
```python
@router.post("/scan/start")
async def start_scan(
    background_tasks: BackgroundTasks,
    target_url: str = Form(...),
    analysis_mode: str = Form("primary_verifiers"),
    scope: str = Form("full"),
    scanner_concurrency: int = Form(20),
    verifier_concurrency: int = Form(10),
    enricher_concurrency: int = Form(5),
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
        enricher_concurrency=enricher_concurrency
    )
    db.add(config)
    db.commit()

    # Trigger Background Task
    background_tasks.add_task(run_pipeline, new_scan.id)

    return {"scan_id": new_scan.id, "status": "queued"}
```

#### New run_pipeline function
```python
async def run_pipeline(scan_id: int):
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
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        scan.status = "failed"
        scan.logs = (scan.logs or "") + f"\nError: {str(e)}"
        db.commit()
    finally:
        db.close()
```

#### New progress endpoint
```python
@router.get("/scan/{scan_id}/progress")
async def get_progress(scan_id: int, db: Session = Depends(get_db)):
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

    # Final findings
    total_findings = db.query(Finding).filter(
        Finding.scan_id == scan_id
    ).count()

    # By severity
    findings_by_severity = {}
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        count = db.query(Finding).filter(
            Finding.scan_id == scan_id,
            Finding.severity == severity
        ).count()
        findings_by_severity[severity.lower()] = count

    return {
        "scan_id": scan_id,
        "chunks": {
            "total": total_chunks,
            "scanned": scanned_chunks,
            "percent": (scanned_chunks / total_chunks * 100) if total_chunks else 0
        },
        "drafts": {
            "total": total_drafts,
            "verified": verified_drafts,
            "rejected": rejected_drafts,
            "pending": total_drafts - verified_drafts - rejected_drafts
        },
        "findings": {
            "total": total_findings,
            "by_severity": findings_by_severity
        }
    }
```

#### Pause/Resume endpoints
```python
@router.post("/scan/{scan_id}/pause")
async def pause_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan and scan.status == "running":
        scan.status = "paused"
        db.commit()
        return {"status": "paused"}
    return {"error": "Cannot pause scan"}

@router.post("/scan/{scan_id}/resume")
async def resume_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan and scan.status == "paused":
        # Recover checkpoint
        checkpoint = ScanCheckpoint(scan_id, db)
        checkpoint.recover()

        scan.status = "running"
        db.commit()

        # Restart pipeline
        background_tasks.add_task(run_pipeline, scan_id)
        return {"status": "resumed"}
    return {"error": "Cannot resume scan"}
```

#### Model config endpoints
```python
@router.get("/models")
async def list_models(db: Session = Depends(get_db)):
    models = db.query(ModelConfig).all()
    return [
        {
            "id": m.id,
            "name": m.name,
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
    max_concurrent: int = Form(2),
    votes: int = Form(1),
    is_analyzer: bool = Form(False),
    is_verifier: bool = Form(False),
    db: Session = Depends(get_db)
):
    model = ModelConfig(
        name=name,
        base_url=base_url,
        api_key=api_key,
        max_concurrent=max_concurrent,
        votes=votes,
        is_analyzer=is_analyzer,
        is_verifier=is_verifier
    )
    db.add(model)
    db.commit()
    return {"id": model.id, "name": model.name}

@router.put("/models/{model_id}")
async def update_model(
    model_id: int,
    max_concurrent: int = Form(None),
    votes: int = Form(None),
    is_analyzer: bool = Form(None),
    is_verifier: bool = Form(None),
    db: Session = Depends(get_db)
):
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
    return {"id": model.id, "updated": True}
```

### 2. Update backend/requirements.txt

Add:
```
tree-sitter-cpp
httpx>=0.25.0
```

### 3. Create init files

Create empty `__init__.py` in:
- backend/app/services/orchestration/
- backend/app/services/intelligence/
- backend/app/services/analysis/

## Testing the API

After implementation:
```bash
# Create a model
curl -X POST http://localhost:8000/models \
  -F "name=llama3.3-70b" \
  -F "base_url=http://localhost:5000" \
  -F "api_key=test" \
  -F "max_concurrent=2" \
  -F "is_analyzer=true"

# Start a scan
curl -X POST http://localhost:8000/scan/start \
  -F "target_url=https://github.com/test/repo.git" \
  -F "analysis_mode=primary_verifiers"

# Check progress
curl http://localhost:8000/scan/1/progress
```
