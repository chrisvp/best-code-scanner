from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Float, JSON, case
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class ModelConfig(Base):
    """LLM model configuration with concurrency settings"""
    __tablename__ = "model_configs"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)  # e.g., "llama3.3-70b"
    base_url = Column(String)
    api_key = Column(String)
    max_tokens = Column(Integer, default=4096)
    max_concurrent = Column(Integer, default=2)  # Concurrency per model
    votes = Column(Integer, default=1)  # Voting weight for consensus
    chunk_size = Column(Integer, default=3000)  # Average tokens per chunk for this model

    is_analyzer = Column(Boolean, default=False)
    is_verifier = Column(Boolean, default=False)

    analysis_prompt_template = Column(Text, nullable=True)
    verification_prompt_template = Column(Text, nullable=True)


class ScanConfig(Base):
    """Per-scan configuration"""
    __tablename__ = "scan_configs"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))

    analysis_mode = Column(String, default="primary_verifiers")  # or "multi_consensus"
    primary_analyzer_id = Column(Integer, ForeignKey("model_configs.id"), nullable=True)
    scope = Column(String, default="full")  # "full" or "incremental"

    # Performance optimizations
    multi_model_scan = Column(Boolean, default=False)  # Use all analyzers or just primary for initial scan
    min_votes_to_verify = Column(Integer, default=1)  # Min votes from initial scan to proceed to verification
    deduplicate_drafts = Column(Boolean, default=True)  # Deduplicate similar drafts before verification

    scanner_concurrency = Column(Integer, default=20)
    verifier_concurrency = Column(Integer, default=10)
    enricher_concurrency = Column(Integer, default=5)
    batch_size = Column(Integer, default=10)  # Batch size for LLM calls
    chunk_size = Column(Integer, default=3000)  # Max tokens per chunk


class ScanFile(Base):
    """File-level tracking for a scan"""
    __tablename__ = "scan_files"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)

    file_path = Column(String, index=True)
    file_hash = Column(String)
    risk_level = Column(String, default="normal")  # high/normal/low
    status = Column(String, default="pending")

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    chunks = relationship("ScanFileChunk", back_populates="scan_file")


class ScanFileChunk(Base):
    """Chunk-level tracking within a file"""
    __tablename__ = "scan_file_chunks"

    id = Column(Integer, primary_key=True)
    scan_file_id = Column(Integer, ForeignKey("scan_files.id"), index=True)

    chunk_index = Column(Integer)
    chunk_type = Column(String)  # "function", "class", "full_file"
    symbol_name = Column(String, nullable=True)
    start_line = Column(Integer)
    end_line = Column(Integer)
    content_hash = Column(String, index=True)

    status = Column(String, default="pending")  # pending/scanning/scanned/failed
    retry_count = Column(Integer, default=0)

    scan_file = relationship("ScanFile", back_populates="chunks")


class Symbol(Base):
    """Indexed code symbol (function, class, variable)"""
    __tablename__ = "symbols"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)

    name = Column(String, index=True)
    qualified_name = Column(String, index=True)
    symbol_type = Column(String)  # "function", "class", "method", "variable"

    file_path = Column(String, index=True)
    start_line = Column(Integer)
    end_line = Column(Integer)

    symbol_metadata = Column(JSON)  # params, return_type, decorators, docstring, etc.


class SymbolReference(Base):
    """Cross-reference: where symbols are used"""
    __tablename__ = "symbol_references"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)

    symbol_id = Column(Integer, ForeignKey("symbols.id"), index=True)
    from_file = Column(String)
    from_line = Column(Integer)
    from_symbol_id = Column(Integer, ForeignKey("symbols.id"), nullable=True)
    reference_type = Column(String)  # "call", "import", "inherit", "type_hint"


class ImportRelation(Base):
    """Module import relationships"""
    __tablename__ = "import_relations"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)

    importer_file = Column(String, index=True)
    imported_module = Column(String)
    imported_names = Column(JSON)  # List of imported names or None
    resolved_file = Column(String, nullable=True)


class VulnerabilityCategory(Base):
    """Standardized vulnerability categories for consistent classification"""
    __tablename__ = "vulnerability_categories"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)  # e.g., "CWE-79 Cross-site Scripting"
    cwe_id = Column(String, nullable=True, index=True)  # e.g., "CWE-79"
    short_name = Column(String, nullable=True)  # e.g., "XSS"
    description = Column(Text, nullable=True)

    # Matching keywords for fuzzy matching
    keywords = Column(JSON)  # e.g., ["xss", "cross-site", "script injection"]

    usage_count = Column(Integer, default=0)  # Track how often this category is used
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class DraftFinding(Base):
    """Initial finding from scanning phase"""
    __tablename__ = "draft_findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)
    chunk_id = Column(Integer, ForeignKey("scan_file_chunks.id"))

    title = Column(String)
    vulnerability_type = Column(String)
    severity = Column(String)
    line_number = Column(Integer)
    snippet = Column(Text)
    reason = Column(Text)

    auto_detected = Column(Boolean, default=False)  # Static detection vs LLM
    initial_votes = Column(Integer, default=1)  # Number of models that detected this during initial scan
    dedup_key = Column(String, index=True)  # Key for deduplication (file+line+type hash)

    status = Column(String, default="pending")  # pending/verifying/verified/rejected
    verification_notes = Column(Text)  # Verifier reasoning for verify/reject decision
    verification_votes = Column(Integer)  # Number of verifiers that agreed

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class VerifiedFinding(Base):
    """Verified finding after verification phase"""
    __tablename__ = "verified_findings"

    id = Column(Integer, primary_key=True)
    draft_id = Column(Integer, ForeignKey("draft_findings.id"))
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)

    title = Column(String)
    confidence = Column(Integer)
    attack_vector = Column(Text)
    data_flow = Column(Text)
    adjusted_severity = Column(String, nullable=True)

    status = Column(String, default="pending")  # pending/enriching/complete
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class LLMCallMetric(Base):
    """Track individual LLM calls for performance analysis"""
    __tablename__ = "llm_call_metrics"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)

    model_name = Column(String, index=True)
    phase = Column(String, index=True)  # "scanner", "verifier", "enricher"

    call_count = Column(Integer, default=1)
    total_time_ms = Column(Float)  # milliseconds
    tokens_in = Column(Integer, nullable=True)
    tokens_out = Column(Integer, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScanMetrics(Base):
    """Scan-level metrics for benchmarking and tuning"""
    __tablename__ = "scan_metrics"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, unique=True)

    # Chunk metrics
    total_chunks = Column(Integer, default=0)
    avg_chunk_tokens = Column(Float, nullable=True)
    min_chunk_tokens = Column(Integer, nullable=True)
    max_chunk_tokens = Column(Integer, nullable=True)
    chunk_size_setting = Column(Integer)  # The configured chunk_size

    # Timing metrics
    total_time_ms = Column(Float, nullable=True)
    ingestion_time_ms = Column(Float, nullable=True)
    indexing_time_ms = Column(Float, nullable=True)
    chunking_time_ms = Column(Float, nullable=True)
    analysis_time_ms = Column(Float, nullable=True)

    # Token throughput
    total_tokens_in = Column(Integer, nullable=True)
    total_tokens_out = Column(Integer, nullable=True)
    tokens_per_second = Column(Float, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
