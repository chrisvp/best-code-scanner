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

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, nullable=True) # Git URL or Filename
    status = Column(String, default=ScanStatus.QUEUED)
    consensus_enabled = Column(Boolean, default=False)
    logs = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    verified_id = Column(Integer, ForeignKey("verified_findings.id"), nullable=True)

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

    scan = relationship("Scan", back_populates="findings")
