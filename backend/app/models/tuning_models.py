"""Database models for prompt tuning system"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, JSON, Boolean
from sqlalchemy.orm import relationship
from app.core.database import Base


def local_now():
    """Return current local datetime for database defaults."""
    return datetime.now().astimezone()


class TuningPromptTemplate(Base):
    """Prompt template variations for tuning"""
    __tablename__ = "tuning_prompt_templates"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    template = Column(Text, nullable=False)  # Contains placeholders: {code}, {claim}, {issue}, {file}

    # Metadata
    created_at = Column(DateTime(timezone=True), default=local_now)
    updated_at = Column(DateTime(timezone=True), onupdate=local_now)

    # Relationships
    results = relationship("TuningResult", back_populates="prompt_template")


class TuningTestCase(Base):
    """Ground truth test cases for verification prompt testing"""
    __tablename__ = "tuning_test_cases"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False, index=True)

    # Ground truth verdict: "FALSE_POSITIVE", "REAL", "WEAKNESS", etc.
    verdict = Column(String, nullable=False, index=True)

    # Reference to draft finding (if created from finding)
    # When set, test case data is pulled from draft_finding at runtime
    draft_finding_id = Column(Integer, ForeignKey("draft_findings.id"), nullable=True, index=True)

    # Test case content (nullable when draft_finding_id is set)
    title = Column(String, nullable=True)  # Finding title
    vulnerability_type = Column(String, nullable=True)  # e.g., "CWE-120 Buffer Overflow"
    severity = Column(String, nullable=True)  # Critical/High/Medium/Low
    line_number = Column(Integer, nullable=True)  # Line number
    snippet = Column(Text, nullable=True)  # Code snippet
    reason = Column(Text, nullable=True)  # Vulnerability reason
    file_path = Column(String, nullable=True)  # Full file path
    language = Column(String, nullable=True)  # Programming language

    # Full context (what verifiers actually see during scans)
    full_code_chunk = Column(Text, nullable=True)  # Complete code chunk from scan
    chunk_id = Column(Integer, ForeignKey("scan_file_chunks.id"), nullable=True)  # Reference to original chunk
    surrounding_lines = Column(Integer, default=10, nullable=True)  # How many lines of context

    # Source scan metadata (for provenance)
    source_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    source_scan_name = Column(String, nullable=True)  # Human-readable scan identifier

    # Historical verification data
    verification_votes_json = Column(JSON, nullable=True)  # Historical votes from models
    consensus_vote = Column(String, nullable=True)  # What the final consensus was
    vote_confidence_avg = Column(Float, nullable=True)  # Average confidence from voters

    # Categorization
    cwe_type = Column(String, nullable=True, index=True)  # e.g., "CWE-120"
    is_synthetic = Column(Boolean, default=False, index=True)  # Real vs synthetic test case
    difficulty_score = Column(Float, nullable=True)  # Estimated difficulty (0-1)

    # Tags for filtering
    tags = Column(JSON, nullable=True)  # ["buffer-overflow", "pointer-arithmetic", "edge-case"]

    # Metadata
    created_at = Column(DateTime(timezone=True), default=local_now)
    updated_at = Column(DateTime(timezone=True), onupdate=local_now)

    # Relationships
    results = relationship("TuningResult", back_populates="test_case")
    draft_finding = relationship("DraftFinding", foreign_keys=[draft_finding_id])


class TuningRun(Base):
    """Test run metadata - tracks a batch of prompt evaluations"""
    __tablename__ = "tuning_runs"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=True)
    description = Column(Text, nullable=True)

    # Configuration
    model_ids = Column(JSON, nullable=False)  # List of model IDs tested
    prompt_ids = Column(JSON, nullable=False)  # List of prompt template IDs tested
    test_case_ids = Column(JSON, nullable=False)  # List of test case IDs tested
    concurrency = Column(Integer, default=4)

    # Status
    status = Column(String, default="running", index=True)  # running, completed, failed

    # Metrics
    total_tests = Column(Integer, default=0)
    completed_tests = Column(Integer, default=0)
    total_duration_ms = Column(Float, nullable=True)

    # Error tracking
    error_message = Column(Text, nullable=True)

    # Timing
    created_at = Column(DateTime(timezone=True), default=local_now)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    results = relationship("TuningResult", back_populates="run", cascade="all, delete-orphan")


class TuningResult(Base):
    """Individual test result - one model + one prompt + one test case = one result"""
    __tablename__ = "tuning_results"

    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("tuning_runs.id"), nullable=False, index=True)

    # Test configuration
    model_id = Column(Integer, ForeignKey("model_configs.id"), nullable=False, index=True)
    model_name = Column(String, nullable=False)  # Denormalized for easier querying
    prompt_id = Column(Integer, ForeignKey("tuning_prompt_templates.id"), nullable=False, index=True)
    test_case_id = Column(Integer, ForeignKey("tuning_test_cases.id"), nullable=False, index=True)

    # Request details
    full_prompt = Column(Text, nullable=False)  # The actual prompt sent (with placeholders filled)
    raw_response = Column(Text, nullable=True)  # Raw LLM response

    # Parsed result
    predicted_vote = Column(String, nullable=True)  # Model's predicted vote
    confidence = Column(Integer, nullable=True)  # Model's confidence (0-100)
    reasoning = Column(Text, nullable=True)  # Model's reasoning

    # Evaluation
    correct = Column(Boolean, default=False, index=True)  # Did prediction match ground truth?
    parse_success = Column(Boolean, default=True)  # Was response parseable?
    parse_error = Column(Text, nullable=True)

    # Performance metrics
    duration_ms = Column(Float, nullable=True)
    tokens_in = Column(Integer, nullable=True)
    tokens_out = Column(Integer, nullable=True)

    # Timing
    created_at = Column(DateTime(timezone=True), default=local_now)

    # Relationships
    run = relationship("TuningRun", back_populates="results")
    # Use string reference for ModelConfig to avoid circular import
    model = relationship("ModelConfig", foreign_keys=[model_id])
    prompt_template = relationship("TuningPromptTemplate", back_populates="results")
    test_case = relationship("TuningTestCase", back_populates="results")
