import sys
import os
import asyncio
import argparse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), "backend"))

from app.core.database import Base
from app.models.scanner_models import ModelConfig, ScanFileChunk, ScanFile
from app.services.orchestration.model_orchestrator import ModelOrchestrator
from app.services.analysis.draft_scanner import DraftScanner
from app.services.orchestration.cache import AnalysisCache

# Mock Cache to avoid persistence
class MockCache:
    def get_analysis(self, *args): return None
    def set_analysis(self, *args): pass
    @staticmethod
    def hash_content(content): return "hash"

async def run_playground(file_path, models, prompt_file=None):
    print(f"=== PROMPT PLAYGROUND ===")
    print(f"Target: {file_path}")
    print(f"Models: {models}")

    # Load custom prompt if provided
    custom_prompt = None
    if prompt_file:
        with open(prompt_file, 'r') as f:
            custom_prompt = f.read()
        print(f"Loaded custom prompt from {prompt_file} ({len(custom_prompt)} chars)")

    # Setup DB (Real DB to access model configs)
    # In a real scenario, we'd connect to the actual DB.
    # For this script, we assume the DB is at /tmp/scans.db or use a fresh one if we just want to test the scanner logic with *mocked* models?
    # No, the user wants to test REAL models. So we need the real DB connection string or params.
    # We'll assume the default SQLite path.
    
    db_url = "sqlite:////tmp/scans.db"
    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    # Initialize Orchestrator
    orchestrator = ModelOrchestrator(db)
    await orchestrator.initialize()

    try:
        # Filter pools
        selected_pools = []
        if "all" in models:
            selected_pools = orchestrator.get_analyzers()
        else:
            for name in models:
                pool = orchestrator.get_pool(name)
                if pool:
                    selected_pools.append(pool)
                else:
                    print(f"Warning: Model {name} not found")

        if not selected_pools:
            print("No valid models found. Exiting.")
            return

        # Apply custom prompt override
        if custom_prompt:
            for pool in selected_pools:
                pool.config.analysis_prompt_template = custom_prompt

        # Read file content
        with open(file_path, 'r') as f:
            content = f.read()

        # Create a dummy chunk for the whole file
        # In reality, we'd chunk it, but for playground we usually want to test one chunk.
        # We'll just create one large chunk (up to limit)
        chunk = ScanFileChunk(
            id=1,
            scan_file_id=1, # Mock
            start_line=1,
            end_line=content.count('\n') + 1,
            content_hash="hash",
            chunk_index=0
        )
        
        # Hack: DraftScanner needs to read the file from disk using ScanFile.file_path.
        # We need to mock that read or ensure the ScanFile exists.
        # Easier to just create a temporary ScanFile record pointing to our target.
        temp_scan_file = ScanFile(id=9999, file_path=file_path, risk_level="high")
        # We need to inject this into the DB session used by DraftScanner...
        # Actually DraftScanner opens its OWN session.
        # So we must commit this temp file to the real DB.
        db.add(temp_scan_file)
        try:
            db.commit()
        except Exception:
            db.rollback() # Might already exist
            # Try to update
            existing = db.query(ScanFile).filter(ScanFile.id == 9999).first()
            if existing:
                existing.file_path = file_path
                db.commit()
        
        chunk.scan_file_id = 9999

        # Run Scanner
        scanner = DraftScanner(scan_id=0, model_pools=selected_pools, cache=MockCache())
        
        print(f"\nScanning with {len(selected_pools)} models...")
        results = await scanner.scan_batch([chunk])
        
        findings = results.get(1, [])
        
        # Display Results
        print(f"\n=== RESULTS ({len(findings)} findings) ===")
        print(f"{ 'Model':<20} | {'Severity':<8} | {'Line':<4} | {'Title'}")
        print("-" * 80)
        
        for f in findings:
            model = f.get('_model', 'Unknown')
            sev = f.get('severity', 'Medium')
            line = f.get('line', 0)
            title = f.get('title', 'Unknown')
            print(f"{model:<20} | {sev:<8} | {line:<4} | {title}")

    finally:
        await orchestrator.shutdown()
        # Cleanup temp file
        db.query(ScanFile).filter(ScanFile.id == 9999).delete()
        db.commit()
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test models and prompts")
    parser.add_argument("file", help="Path to code file")
    parser.add_argument("--models", default="all", help="Comma-separated model names or 'all'")
    parser.add_argument("--prompt", help="Path to custom prompt file")
    
    args = parser.parse_args()
    models_list = [m.strip() for m in args.models.split(",")]
    
    asyncio.run(run_playground(args.file, models_list, args.prompt))
