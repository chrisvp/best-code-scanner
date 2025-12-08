from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel

from app.core.database import get_db
from app.models.scanner_models import BenchmarkDataset, BenchmarkRun, BenchmarkResult, ModelConfig
from app.services.analysis.benchmark_service import BenchmarkService

router = APIRouter()

class BenchmarkRunRequest(BaseModel):
    dataset_id: int
    model_id: int
    prompt_template: Optional[str] = None

@router.get("/datasets")
def get_datasets(db: Session = Depends(get_db)):
    service = BenchmarkService(db)
    service.ensure_default_dataset() # Ensure defaults exist
    return db.query(BenchmarkDataset).all()

@router.get("/runs")
def get_runs(db: Session = Depends(get_db)):
    return db.query(BenchmarkRun).order_by(BenchmarkRun.created_at.desc()).limit(50).all()

@router.get("/run/{run_id}")
def get_run_details(run_id: int, db: Session = Depends(get_db)):
    run = db.query(BenchmarkRun).filter(BenchmarkRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {
        "run": run,
        "results": db.query(BenchmarkResult).filter(BenchmarkResult.run_id == run_id).all()
    }

@router.post("/run")
async def start_benchmark(
    request: BenchmarkRunRequest, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    service = BenchmarkService(db)
    
    # Quick check
    dataset = db.query(BenchmarkDataset).filter(BenchmarkDataset.id == request.dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
        
    # Run in background (it's slow)
    background_tasks.add_task(
        service.run_benchmark, 
        request.dataset_id, 
        request.model_id, 
        request.prompt_template
    )
    
    return {"status": "started", "message": "Benchmark started in background"}
