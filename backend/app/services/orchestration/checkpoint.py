from sqlalchemy.orm import Session
from app.models.scanner_models import ScanFile, ScanFileChunk, DraftFinding, VerifiedFinding


class ScanCheckpoint:
    """Manages pause/resume and crash recovery for scans"""

    def __init__(self, scan_id: int, db: Session):
        self.scan_id = scan_id
        self.db = db

    def save(self):
        """
        Save checkpoint state.
        State is maintained in DB via status fields, so this is mostly a commit.
        """
        self.db.commit()

    def recover(self):
        """
        Recover from pause or crash.
        Reset any in-progress items back to pending so they can be reprocessed.
        """
        # Reset chunks that were being scanned
        self.db.query(ScanFileChunk).filter(
            ScanFileChunk.scan_file_id.in_(
                self.db.query(ScanFile.id).filter(ScanFile.scan_id == self.scan_id)
            ),
            ScanFileChunk.status == "scanning"
        ).update({"status": "pending"}, synchronize_session=False)

        # Reset drafts that were being verified
        self.db.query(DraftFinding).filter(
            DraftFinding.scan_id == self.scan_id,
            DraftFinding.status == "verifying"
        ).update({"status": "pending"}, synchronize_session=False)

        # Reset verified findings that were being enriched
        self.db.query(VerifiedFinding).filter(
            VerifiedFinding.scan_id == self.scan_id,
            VerifiedFinding.status == "enriching"
        ).update({"status": "pending"}, synchronize_session=False)

        self.db.commit()

    def get_progress(self) -> dict:
        """Get current progress for checkpointing"""
        from sqlalchemy import func

        # Count chunks by status
        chunk_counts = self.db.query(
            ScanFileChunk.status,
            func.count(ScanFileChunk.id)
        ).join(ScanFile).filter(
            ScanFile.scan_id == self.scan_id
        ).group_by(ScanFileChunk.status).all()

        # Count drafts by status
        draft_counts = self.db.query(
            DraftFinding.status,
            func.count(DraftFinding.id)
        ).filter(
            DraftFinding.scan_id == self.scan_id
        ).group_by(DraftFinding.status).all()

        # Count verified by status
        verified_counts = self.db.query(
            VerifiedFinding.status,
            func.count(VerifiedFinding.id)
        ).filter(
            VerifiedFinding.scan_id == self.scan_id
        ).group_by(VerifiedFinding.status).all()

        return {
            "chunks": dict(chunk_counts),
            "drafts": dict(draft_counts),
            "verified": dict(verified_counts)
        }
