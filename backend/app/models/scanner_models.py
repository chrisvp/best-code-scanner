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
    is_cleanup = Column(Boolean, default=False)  # Model for cleaning up malformed LLM responses
    is_chat = Column(Boolean, default=False)  # Default model for chat interface

    analysis_prompt_template = Column(Text, nullable=True)
    verification_prompt_template = Column(Text, nullable=True)


class ScanConfig(Base):
    """Per-scan configuration"""
    __tablename__ = "scan_configs"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    profile_id = Column(Integer, ForeignKey("scan_profiles.id"), nullable=True)  # Link to scan profile

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
    batch_size = Column(Integer, default=5)  # Batch size for LLM calls
    chunk_size = Column(Integer, default=6000)  # Max tokens per chunk
    chunk_strategy = Column(String, default="smart")  # lines, functions, or smart
    file_filter = Column(String, nullable=True)  # Glob pattern to filter files (e.g., "*.c", "src/*.py", "sshd.c")


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
    last_error = Column(Text, nullable=True)  # Last error message
    next_retry_at = Column(DateTime(timezone=True), nullable=True)  # For exponential backoff

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
    source_models = Column(JSON, nullable=True)  # List of model names that detected this finding
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


class StaticRule(Base):
    """Static detection rules - regex patterns for known vulnerabilities"""
    __tablename__ = "static_rules"

    id = Column(Integer, primary_key=True)
    name = Column(String, index=True)  # Human-readable name
    description = Column(Text, nullable=True)

    # Matching criteria
    pattern = Column(String)  # Regex pattern
    languages = Column(JSON)  # List of languages: ["c", "cpp", "py"]

    # Classification
    cwe_id = Column(String, nullable=True)  # e.g., "CWE-78"
    vulnerability_type = Column(String)  # e.g., "Command Injection"
    severity = Column(String, default="High")  # Critical/High/Medium/Low

    # Behavior
    is_definite = Column(Boolean, default=True)  # True = auto-create finding, False = flag for LLM
    requires_llm_verification = Column(Boolean, default=False)  # Skip verification phase

    # Metadata
    enabled = Column(Boolean, default=True)
    built_in = Column(Boolean, default=True)  # False for user-created rules
    match_count = Column(Integer, default=0)  # Track how often this rule matches

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class ScanProfile(Base):
    """Reusable scan configuration profiles"""
    __tablename__ = "scan_profiles"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)  # e.g., "Quick Scan", "Deep C Audit"
    description = Column(Text, nullable=True)
    is_default = Column(Boolean, default=False)

    # Default scan settings
    chunk_size = Column(Integer, default=6000)
    chunk_strategy = Column(String, default="smart")

    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    analyzers = relationship("ProfileAnalyzer", back_populates="profile", order_by="ProfileAnalyzer.run_order")


class ProfileAnalyzer(Base):
    """Configurable analyzer within a profile - pairs prompt with model"""
    __tablename__ = "profile_analyzers"

    id = Column(Integer, primary_key=True)
    profile_id = Column(Integer, ForeignKey("scan_profiles.id"), index=True)

    name = Column(String)  # e.g., "General Security", "C Memory Safety", "Signal Handler Audit"
    description = Column(Text, nullable=True)

    # Model configuration
    model_id = Column(Integer, ForeignKey("model_configs.id"), nullable=True)  # If null, use default

    # Prompt template - supports {code}, {language}, {file_path} placeholders
    prompt_template = Column(Text)

    # Filtering
    file_filter = Column(String, nullable=True)  # Glob pattern: "*.c,*.h" or null for all
    language_filter = Column(JSON, nullable=True)  # ["c", "cpp"] or null for all

    # Role and ordering
    role = Column(String, default="analyzer")  # analyzer, verifier, enricher
    run_order = Column(Integer, default=1)  # Order within the profile

    # Behavior
    enabled = Column(Boolean, default=True)
    stop_on_findings = Column(Boolean, default=False)  # Stop subsequent analyzers if this finds issues
    min_severity_to_report = Column(String, nullable=True)  # Only report findings >= this severity

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    profile = relationship("ScanProfile", back_populates="analyzers")
    model = relationship("ModelConfig")


class WebhookConfig(Base):
    """Webhook configuration for security alerts"""
    __tablename__ = "webhook_configs"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    secret = Column(String, nullable=True)  # For HMAC-SHA256 signing
    events = Column(JSON)  # ["malicious_intent", "critical_finding", "scan_complete"]
    min_severity = Column(String, default="High")  # CRITICAL, HIGH, MEDIUM, LOW
    enabled = Column(Boolean, default=True)

    # Stats
    last_triggered = Column(DateTime(timezone=True), nullable=True)
    trigger_count = Column(Integer, default=0)
    last_error = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    deliveries = relationship("WebhookDeliveryLog", back_populates="webhook")


class WebhookDeliveryLog(Base):
    """Log of webhook delivery attempts"""
    __tablename__ = "webhook_delivery_logs"

    id = Column(Integer, primary_key=True)
    webhook_id = Column(Integer, ForeignKey("webhook_configs.id"), index=True)

    event_type = Column(String, index=True)  # malicious_intent, critical_finding, scan_complete
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    finding_id = Column(Integer, nullable=True)  # Reference to draft or verified finding

    payload = Column(JSON)  # The actual payload sent

    # Delivery status
    status = Column(String, default="pending")  # pending, success, failed
    status_code = Column(Integer, nullable=True)  # HTTP status code
    response_body = Column(Text, nullable=True)  # Response from webhook endpoint
    error_message = Column(String, nullable=True)

    # Timing
    attempt_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    delivered_at = Column(DateTime(timezone=True), nullable=True)

    webhook = relationship("WebhookConfig", back_populates="deliveries")


class ScanErrorLog(Base):
    """Detailed error log for tracking failures and enabling recovery"""
    __tablename__ = "scan_error_logs"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)
    chunk_id = Column(Integer, ForeignKey("scan_file_chunks.id"), nullable=True)

    phase = Column(String, index=True)  # "scanner", "verifier", "enricher"
    error_type = Column(String)  # "timeout", "rate_limit", "model_error", "parse_error", "unknown"
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)

    # Context for debugging
    model_name = Column(String, nullable=True)
    file_path = Column(String, nullable=True)
    chunk_index = Column(Integer, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)  # When successfully retried


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


class RepoWatcher(Base):
    """Configuration for watching a GitLab repository for MR security reviews"""
    __tablename__ = "repo_watchers"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)  # Human-readable name for this watcher
    gitlab_url = Column(String, nullable=False)  # e.g., https://gitlab.com
    gitlab_token = Column(String)  # Encrypted access token
    project_id = Column(String, nullable=False)  # GitLab project ID or path (e.g., "group/project")
    branch_filter = Column(String, nullable=True)  # Regex or glob pattern for branches to watch
    label_filter = Column(String, nullable=True)  # Comma-separated labels to filter MRs

    # Configuration references
    scan_profile_id = Column(Integer, ForeignKey("scan_profiles.id"), nullable=True)
    review_model_id = Column(Integer, ForeignKey("model_configs.id"), nullable=True)
    webhook_id = Column(Integer, ForeignKey("webhook_configs.id"), nullable=True)  # For alerts

    # Watcher state
    status = Column(String, default="paused")  # running, paused, error
    enabled = Column(Boolean, default=True)
    poll_interval = Column(Integer, default=300)  # Seconds between checks
    post_comments = Column(Boolean, default=False)  # If False, only track findings locally (dry run mode)
    last_check = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    scan_profile = relationship("ScanProfile")
    review_model = relationship("ModelConfig")
    webhook = relationship("WebhookConfig")
    reviews = relationship("MRReview", back_populates="watcher")


class MRReview(Base):
    """Tracking for individual merge request reviews"""
    __tablename__ = "mr_reviews"

    id = Column(Integer, primary_key=True)
    watcher_id = Column(Integer, ForeignKey("repo_watchers.id"), nullable=False, index=True)

    # GitLab MR identification
    mr_iid = Column(Integer, nullable=False)  # GitLab MR internal ID within project
    mr_title = Column(String, nullable=True)
    mr_url = Column(String, nullable=True)
    mr_author = Column(String, nullable=True)
    source_branch = Column(String, nullable=True)
    target_branch = Column(String, nullable=True)

    # Review status
    status = Column(String, default="pending")  # pending, reviewing, completed, error

    # Phase 1: Diff review results (fast inline feedback)
    diff_findings = Column(JSON, nullable=True)  # List of inline comments from diff analysis
    diff_summary = Column(Text, nullable=True)  # Overall summary comment
    diff_reviewed_at = Column(DateTime(timezone=True), nullable=True)

    # Phase 2: Full file scan results (deep analysis)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)  # Link to full security scan
    scan_started_at = Column(DateTime(timezone=True), nullable=True)
    scan_completed_at = Column(DateTime(timezone=True), nullable=True)

    # GitLab interaction tracking
    generated_comments = Column(JSON, nullable=True)  # Pre-formatted comments ready for GitLab (stored even in dry-run)
    comments_posted = Column(JSON, nullable=True)  # List of posted comment IDs for deduplication
    approval_status = Column(String, nullable=True)  # approved, changes_requested, pending

    # Error tracking
    last_error = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    watcher = relationship("RepoWatcher", back_populates="reviews")
    scan = relationship("Scan")
