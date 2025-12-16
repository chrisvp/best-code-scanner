#!/usr/bin/env python3
"""
Restart a stuck scan by manually triggering the pipeline.
Usage: python restart_scan.py <scan_id>
"""
import sys
import asyncio
from app.core.database import SessionLocal
from app.models.models import Scan
from app.models.scanner_models import ScanConfig

async def restart_scan(scan_id: int):
    from app.services.orchestration.pipeline import ScanPipeline

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            print(f"Error: Scan {scan_id} not found")
            return

        print(f"Scan {scan_id} current status: {scan.status}, phase: {scan.current_phase}")

        # Get config
        config = db.query(ScanConfig).filter(ScanConfig.scan_id == scan_id).order_by(ScanConfig.id.desc()).first()
        if not config:
            print(f"Error: No config found for scan {scan_id}")
            return

        print(f"Restarting pipeline for scan {scan_id}...")

        # Run pipeline
        pipeline = ScanPipeline(scan_id, config, db)
        await pipeline.run()

        # Update status
        scan.status = "completed"
        db.commit()

        print(f"Scan {scan_id} completed successfully")

    except Exception as e:
        import traceback
        print(f"Pipeline error: {traceback.format_exc()}")
        db.rollback()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            scan.status = "failed"
            scan.logs = (scan.logs or "") + f"\nError: {str(e)}"
            db.commit()
            print(f"Scan {scan_id} marked as failed")
        except Exception:
            db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python restart_scan.py <scan_id>")
        sys.exit(1)

    scan_id = int(sys.argv[1])
    asyncio.run(restart_scan(scan_id))
