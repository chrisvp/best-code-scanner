from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum, Boolean, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from app.core.database import Base

class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanPhase(str, enum.Enum):
    """Tracks which phase of the scan pipeline we're in"""
    QUEUED = "queued"
    INGESTION = "ingestion"
    INDEXING = "indexing"
    CHUNKING = "chunking"
    SCANNING = "scanning"
    VERIFYING = "verifying"
    ENRICHING = "enriching"
    COMPLETED = "completed"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, nullable=True) # Git URL or Filename
    status = Column(String, default=ScanStatus.QUEUED, index=True)
    current_phase = Column(String, default=ScanPhase.QUEUED, index=True)  # Track pipeline progress for resume
    consensus_enabled = Column(Boolean, default=False)
    logs = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    verified_id = Column(Integer, ForeignKey("verified_findings.id"), nullable=True)
    mr_review_id = Column(Integer, ForeignKey("mr_reviews.id"), nullable=True, index=True)

    file_path = Column(String, nullable=False)
    line_number = Column(Integer, nullable=True)
    severity = Column(String, default="Medium")  # Low, Medium, High, Critical
    description = Column(Text, nullable=False)
    snippet = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)

    # Extended fields for enriched findings
    category = Column(String, nullable=True)  # CWE category
    cvss_score = Column(Float, nullable=True)
    vulnerability_details = Column(Text, nullable=True)
    proof_of_concept = Column(Text, nullable=True)
    corrected_code = Column(Text, nullable=True)
    remediation_steps = Column(Text, nullable=True)
    references = Column(Text, nullable=True)

    # Detection metadata
    source_model = Column(String, nullable=True)  # Model that detected this finding
    detected_at = Column(DateTime(timezone=True), nullable=True)  # When the finding was detected
    confidence_score = Column(Float, nullable=True)  # Model's confidence in the finding

    scan = relationship("Scan", back_populates="findings")
    # MRReview is defined in scanner_models.py
    mr_review = relationship("MRReview", back_populates="findings")
    generated_fixes = relationship("GeneratedFix", back_populates="finding", order_by="GeneratedFix.created_at.desc()")


class GeneratedFix(Base):
    """Stores generated fixes for a finding - allows cycling between multiple suggestions"""
    __tablename__ = "generated_fixes"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    fix_type = Column(String, nullable=False)  # 'quick' or 'agent'
    model_name = Column(String, nullable=True)
    code = Column(Text, nullable=False)
    reasoning = Column(Text, nullable=True)  # JSON list for agent fixes
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    finding = relationship("Finding", back_populates="generated_fixes")
