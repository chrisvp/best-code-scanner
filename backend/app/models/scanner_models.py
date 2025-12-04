from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Float, JSON, case
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


def local_now():
    """Return current local datetime for database defaults."""
    return datetime.now().astimezone()


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
    source_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)  # Reuse sandbox from this scan


class ScanFile(Base):
    """File-level tracking for a scan"""
    __tablename__ = "scan_files"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)

    file_path = Column(String, index=True)
    file_hash = Column(String)
    risk_level = Column(String, default="normal")  # high/normal/low
    status = Column(String, default="pending")

    created_at = Column(DateTime(timezone=True), default=local_now)

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

    status = Column(String, default="pending", index=True)  # pending/scanning/scanned/failed
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
    created_at = Column(DateTime(timezone=True), default=local_now)


class DraftFinding(Base):
    """Initial finding from scanning phase"""
    __tablename__ = "draft_findings"

    # Status values:
    # - pending: Awaiting verification
    # - verifying: Currently being verified
    # - verified: Confirmed vulnerability, will be enriched
    # - weakness: Confirmed code quality issue, skips enrichment, not counted as vulnerability
    # - rejected: False positive, discarded

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

    status = Column(String, default="pending", index=True)  # pending/verifying/verified/weakness/rejected
    verification_notes = Column(Text)  # Verifier reasoning for verify/reject decision
    verification_votes = Column(Integer)  # Number of verifiers that agreed

    created_at = Column(DateTime(timezone=True), default=local_now)

    # Relationship to votes for debugging
    votes = relationship("VerificationVote", back_populates="draft_finding")


class VerifiedFinding(Base):
    """Verified finding after verification phase"""
    __tablename__ = "verified_findings"

    id = Column(Integer, primary_key=True)
    draft_id = Column(Integer, ForeignKey("draft_findings.id"), index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)

    title = Column(String)
    confidence = Column(Integer)
    attack_vector = Column(Text)
    data_flow = Column(Text)
    adjusted_severity = Column(String, nullable=True)

    status = Column(String, default="pending")  # pending/enriching/complete
    created_at = Column(DateTime(timezone=True), default=local_now)


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

    created_at = Column(DateTime(timezone=True), default=local_now)


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

    created_at = Column(DateTime(timezone=True), default=local_now)
    updated_at = Column(DateTime(timezone=True), onupdate=local_now)


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

    # Enricher configuration (single model per profile)
    enricher_model_id = Column(Integer, ForeignKey("model_configs.id"), nullable=True)
    enricher_prompt_template = Column(Text, nullable=True)

    # Agentic verifier configuration
    agentic_verifier_mode = Column(String, default="skip")  # "skip", "hybrid", "full"
    agentic_verifier_model_id = Column(Integer, ForeignKey("model_configs.id"), nullable=True)
    agentic_verifier_max_steps = Column(Integer, default=8)  # Max reasoning steps

    # Verification settings
    verification_threshold = Column(Integer, default=2)  # Min votes to verify (e.g., 2 of 3)
    require_unanimous_reject = Column(Boolean, default=False)  # All must reject to reject

    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=local_now)
    updated_at = Column(DateTime(timezone=True), onupdate=local_now)

    # Relationships
    analyzers = relationship("ProfileAnalyzer", back_populates="profile", order_by="ProfileAnalyzer.run_order")
    verifiers = relationship("ProfileVerifier", back_populates="profile", order_by="ProfileVerifier.run_order")
    enricher_model = relationship("ModelConfig", foreign_keys=[enricher_model_id])
    agentic_verifier_model = relationship("ModelConfig", foreign_keys=[agentic_verifier_model_id])


class ProfileAnalyzer(Base):
    """Configurable analyzer within a profile - pairs prompt with model"""
    __tablename__ = "profile_analyzers"

    id = Column(Integer, primary_key=True)
    profile_id = Column(Integer, ForeignKey("scan_profiles.id"), index=True)

    name = Column(String)  # e.g., "General Security", "C Memory Safety", "Signal Handler Audit"
    description = Column(Text, nullable=True)

    # Model configuration
    model_id = Column(Integer, ForeignKey("model_configs.id"), nullable=False)

    # Chunk size for this analyzer (tokens)
    chunk_size = Column(Integer, default=6000)

    # Prompt template - supports {code}, {language}, {file_path} placeholders
    prompt_template = Column(Text)

    # Output mode: how to parse LLM responses
    # - "markers": Use *DRAFT:, *VOTE:, etc. markers (default, works everywhere)
    # - "json": Use response_format: json_object (wider model support)
    # - "guided_json": Use vLLM guided_json with schema (strictest, limited model support)
    output_mode = Column(String, default="markers")
    json_schema = Column(Text, nullable=True)  # JSON schema for guided_json mode

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

    created_at = Column(DateTime(timezone=True), default=local_now)

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

    created_at = Column(DateTime(timezone=True), default=local_now)
    updated_at = Column(DateTime(timezone=True), onupdate=local_now)

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
    created_at = Column(DateTime(timezone=True), default=local_now)
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

    created_at = Column(DateTime(timezone=True), default=local_now)
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

    created_at = Column(DateTime(timezone=True), default=local_now)


class GitLabRepo(Base):
    """Stored GitLab repository connection for reuse across MR reviews and watchers"""
    __tablename__ = "gitlab_repos"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)  # Human-readable name (e.g., "Main Firmware Repo")
    gitlab_url = Column(String, nullable=False, default="https://192.168.33.158")  # GitLab instance URL
    gitlab_token = Column(String)  # Access token (stored encrypted ideally)
    project_id = Column(String, nullable=False)  # Project ID or path (e.g., "12345" or "group/project")
    description = Column(String, nullable=True)  # Optional description
    verify_ssl = Column(Boolean, default=False)  # Whether to verify SSL certs (False for self-hosted)

    created_at = Column(DateTime(timezone=True), default=local_now)
    updated_at = Column(DateTime(timezone=True), onupdate=local_now)

    # Relationships
    watchers = relationship("RepoWatcher", back_populates="gitlab_repo")


class GitHubRepo(Base):
    """Stored GitHub repository connection for reuse across PR reviews and watchers"""
    __tablename__ = "github_repos"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)  # Human-readable name (e.g., "Linux Kernel")
    github_url = Column(String, nullable=False, default="https://api.github.com")  # GitHub API URL
    github_token = Column(String)  # Personal access token or fine-grained token
    owner = Column(String, nullable=False)  # Repository owner (user or org)
    repo = Column(String, nullable=False)  # Repository name
    description = Column(String, nullable=True)  # Optional description

    created_at = Column(DateTime(timezone=True), default=local_now)
    updated_at = Column(DateTime(timezone=True), onupdate=local_now)

    # Relationships
    watchers = relationship("RepoWatcher", back_populates="github_repo")


class RepoWatcher(Base):
    """Configuration for watching a Git repository (GitLab or GitHub) for MR/PR security reviews"""
    __tablename__ = "repo_watchers"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)  # Human-readable name for this watcher

    # Provider type: "gitlab" (internal) or "github" (external)
    provider = Column(String, default="gitlab")  # gitlab or github

    # GitLab connection - can use saved repo or manual entry
    gitlab_repo_id = Column(Integer, ForeignKey("gitlab_repos.id"), nullable=True)
    # Fallback fields if not using a saved repo (kept for backwards compatibility)
    gitlab_url = Column(String, nullable=True)  # e.g., https://gitlab.com
    gitlab_token = Column(String, nullable=True)  # Encrypted access token
    project_id = Column(String, nullable=True)  # GitLab project ID or path (e.g., "group/project")

    # GitHub connection - can use saved repo or manual entry
    github_repo_id = Column(Integer, ForeignKey("github_repos.id"), nullable=True)
    # Fallback fields for GitHub manual entry
    github_url = Column(String, nullable=True, default="https://api.github.com")  # GitHub API URL
    github_token = Column(String, nullable=True)  # Personal access token
    github_owner = Column(String, nullable=True)  # Repository owner (user or org)
    github_repo_name = Column(String, nullable=True)  # Repository name

    branch_filter = Column(String, nullable=True)  # Regex or glob pattern for branches to watch
    label_filter = Column(String, nullable=True)  # Comma-separated labels to filter MRs/PRs

    # Configuration references
    scan_profile_id = Column(Integer, ForeignKey("scan_profiles.id"), nullable=True)
    review_model_id = Column(Integer, ForeignKey("model_configs.id"), nullable=True)
    webhook_id = Column(Integer, ForeignKey("webhook_configs.id"), nullable=True)  # For alerts

    # Watcher state
    status = Column(String, default="paused")  # running, paused, error
    enabled = Column(Boolean, default=True)
    poll_interval = Column(Integer, default=300)  # Seconds between checks
    post_comments = Column(Boolean, default=False)  # If False, only track findings locally (dry run mode)
    max_files_to_review = Column(Integer, default=100)  # Skip MRs/PRs with more changed files than this (prevents rebase floods)
    mr_lookback_days = Column(Integer, default=7)  # Only review MRs/PRs created in the last N days (0 = no limit)
    last_check = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), default=local_now)
    updated_at = Column(DateTime(timezone=True), onupdate=local_now)

    # Relationships
    gitlab_repo = relationship("GitLabRepo", back_populates="watchers")
    github_repo = relationship("GitHubRepo", back_populates="watchers")
    scan_profile = relationship("ScanProfile")
    review_model = relationship("ModelConfig")
    webhook = relationship("WebhookConfig")
    reviews = relationship("MRReview", back_populates="watcher")


class LLMRequestLog(Base):
    """Log of all LLM requests and responses for debugging parsing issues"""
    __tablename__ = "llm_request_logs"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    mr_review_id = Column(Integer, ForeignKey("mr_reviews.id"), nullable=True, index=True)

    # Request status: "pending", "completed", "failed", "timeout"
    status = Column(String, default="pending", index=True)

    # Request context
    model_name = Column(String, index=True)
    phase = Column(String, index=True)  # "scanner", "verifier", "enricher", "chat", "cleanup", "mr_review"
    analyzer_name = Column(String, nullable=True)  # Name of the analyzer/profile used

    # File context
    file_path = Column(String, nullable=True)
    chunk_id = Column(Integer, nullable=True)

    # Request/Response content
    request_prompt = Column(Text)  # The full prompt sent to the LLM
    raw_response = Column(Text, nullable=True)  # The raw response from the LLM (nullable until completed)
    parsed_result = Column(JSON, nullable=True)  # What was successfully parsed (findings, etc.)

    # Parsing status
    parse_success = Column(Boolean, default=True)
    parse_error = Column(Text, nullable=True)  # Error message if parsing failed
    findings_count = Column(Integer, default=0)  # Number of findings parsed

    # Performance metrics
    tokens_in = Column(Integer, nullable=True)
    tokens_out = Column(Integer, nullable=True)
    duration_ms = Column(Float, nullable=True)

    created_at = Column(DateTime(timezone=True), default=local_now)


class AgentVerificationSession(Base):
    """Log of agent verification sessions with full execution trace"""
    __tablename__ = "agent_verification_sessions"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=True, index=True)
    draft_finding_id = Column(Integer, ForeignKey("draft_findings.id"), nullable=True, index=True)

    # Session status: "running", "completed", "failed", "max_steps"
    status = Column(String, default="running", index=True)

    # Model used for verification
    model_name = Column(String, nullable=True)

    # Verification result
    verdict = Column(String, nullable=True)  # "VERIFIED", "REJECTED", or None if incomplete
    confidence = Column(Integer, nullable=True)  # 0-100
    reasoning = Column(Text, nullable=True)
    attack_path = Column(Text, nullable=True)

    # Execution metrics
    total_steps = Column(Integer, default=0)
    max_steps = Column(Integer, default=8)
    total_tokens = Column(Integer, default=0)
    duration_ms = Column(Float, nullable=True)

    # Full execution trace (JSON array of steps)
    execution_trace = Column(JSON, nullable=True)

    # Task and context
    task_prompt = Column(Text, nullable=True)
    prefetched_context = Column(JSON, nullable=True)  # What was pre-fetched for the agent

    # Error info if failed
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=local_now)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class MRReview(Base):
    """Tracking for individual merge request / pull request reviews"""
    __tablename__ = "mr_reviews"

    id = Column(Integer, primary_key=True)
    watcher_id = Column(Integer, ForeignKey("repo_watchers.id"), nullable=True, index=True)  # Nullable for manual reviews
    gitlab_repo_id = Column(Integer, ForeignKey("gitlab_repos.id"), nullable=True, index=True)  # For manual reviews with saved repo
    github_repo_id = Column(Integer, ForeignKey("github_repos.id"), nullable=True, index=True)  # For GitHub PR reviews

    # Provider type: "gitlab" or "github"
    provider = Column(String, default="gitlab")  # gitlab or github

    # MR/PR identification (works for both GitLab MRs and GitHub PRs)
    mr_iid = Column(Integer, nullable=False)  # MR/PR number within project
    mr_title = Column(String, nullable=True)
    mr_url = Column(String, nullable=True)
    mr_author = Column(String, nullable=True)
    source_branch = Column(String, nullable=True)
    target_branch = Column(String, nullable=True)

    # Review status
    status = Column(String, default="pending")  # pending, reviewing, completed, error
    files_reviewed = Column(Integer, default=0)  # Number of files analyzed
    post_comments = Column(Boolean, default=False)  # Whether to post comments to GitLab/GitHub

    # Phase 1: Diff review results (fast inline feedback)
    diff_findings = Column(JSON, nullable=True)  # List of inline comments from diff analysis
    diff_summary = Column(Text, nullable=True)  # Overall summary comment
    diff_reviewed_at = Column(DateTime(timezone=True), nullable=True)

    # Phase 2: Full file scan results (deep analysis)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)  # Link to full security scan
    scan_started_at = Column(DateTime(timezone=True), nullable=True)
    scan_completed_at = Column(DateTime(timezone=True), nullable=True)

    # Git provider interaction tracking
    generated_comments = Column(JSON, nullable=True)  # Pre-formatted comments ready for GitLab/GitHub (stored even in dry-run)
    comments_posted = Column(JSON, nullable=True)  # List of posted comment IDs for deduplication
    approval_status = Column(String, nullable=True)  # approved, changes_requested, pending

    # Error tracking
    last_error = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), default=local_now)
    updated_at = Column(DateTime(timezone=True), onupdate=local_now)

    # Relationships
    watcher = relationship("RepoWatcher", back_populates="reviews")
    gitlab_repo = relationship("GitLabRepo")
    github_repo = relationship("GitHubRepo")
    scan = relationship("Scan")
    findings = relationship("Finding", back_populates="mr_review")


class ProfileVerifier(Base):
    """Configurable verifier within a profile - pairs prompt with model for verification phase"""
    __tablename__ = "profile_verifiers"

    id = Column(Integer, primary_key=True)
    profile_id = Column(Integer, ForeignKey("scan_profiles.id"), index=True)

    name = Column(String)  # e.g., "Strict Security Verifier", "Memory Safety Expert"
    description = Column(Text, nullable=True)

    # Model configuration
    model_id = Column(Integer, ForeignKey("model_configs.id"), nullable=False)

    # Prompt template - supports {title}, {vuln_type}, {severity}, {snippet}, {reason}, {context}
    prompt_template = Column(Text)

    # Output mode: how to parse LLM responses
    # - "markers": Use *VOTE:, *CONFIDENCE:, etc. markers (default, works everywhere)
    # - "json": Use response_format: json_object (wider model support)
    # - "guided_json": Use vLLM guided_json with schema (strictest, limited model support)
    output_mode = Column(String, default="markers")
    json_schema = Column(Text, nullable=True)  # JSON schema for guided_json mode

    # Voting configuration
    vote_weight = Column(Float, default=1.0)  # Weight in voting (e.g., 1.5 for expert models)
    min_confidence = Column(Integer, default=0)  # Minimum confidence to count vote

    # Ordering and state
    run_order = Column(Integer, default=1)
    enabled = Column(Boolean, default=True)

    created_at = Column(DateTime(timezone=True), default=local_now)

    # Relationships
    profile = relationship("ScanProfile", back_populates="verifiers")
    model = relationship("ModelConfig")


class VerificationVote(Base):
    """Individual vote record from a verifier model - for debugging and analysis"""
    __tablename__ = "verification_votes"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)
    draft_finding_id = Column(Integer, ForeignKey("draft_findings.id"), index=True)

    # Voter info
    model_name = Column(String, index=True)
    verifier_id = Column(Integer, ForeignKey("profile_verifiers.id"), nullable=True)  # Null for legacy votes

    # Vote details
    decision = Column(String)  # VERIFY, WEAKNESS, REJECT, ABSTAIN
    confidence = Column(Integer)  # 0-100
    reasoning = Column(Text, nullable=True)
    attack_scenario = Column(Text, nullable=True)

    # Parsing metadata
    raw_response = Column(Text, nullable=True)  # Full response for debugging
    parse_success = Column(Boolean, default=True)
    format_detected = Column(String, nullable=True)  # json, marker, unknown

    # Weighting
    vote_weight = Column(Float, default=1.0)  # Applied weight

    created_at = Column(DateTime(timezone=True), default=local_now)

    # Relationships
    draft_finding = relationship("DraftFinding")
    verifier = relationship("ProfileVerifier")


class GlobalSetting(Base):
    """Global application settings - key-value store"""
    __tablename__ = "global_settings"

    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)
    value_type = Column(String, default="string")  # string, int, bool, json
    description = Column(Text, nullable=True)

    updated_at = Column(DateTime(timezone=True), default=local_now, onupdate=local_now)

    @classmethod
    def get(cls, db, key: str, default=None):
        """Get a setting value by key"""
        setting = db.query(cls).filter(cls.key == key).first()
        if not setting:
            return default

        # Type coercion
        if setting.value_type == "int":
            return int(setting.value) if setting.value else default
        elif setting.value_type == "bool":
            return setting.value.lower() in ("true", "1", "yes") if setting.value else default
        elif setting.value_type == "json":
            import json
            return json.loads(setting.value) if setting.value else default
        return setting.value

    @classmethod
    def set(cls, db, key: str, value, value_type: str = "string", description: str = None):
        """Set a setting value"""
        import json as json_module

        setting = db.query(cls).filter(cls.key == key).first()
        if not setting:
            setting = cls(key=key)
            db.add(setting)

        setting.value_type = value_type
        if value_type == "json":
            setting.value = json_module.dumps(value)
        else:
            setting.value = str(value) if value is not None else None

        if description:
            setting.description = description

        db.commit()
        return setting
