# Implement Scanner Database Models

Create all database models for the security scanner refactoring.

## Task

Create `backend/app/models/scanner_models.py` with complete SQLAlchemy models.

## Models to Create

### ModelConfig
```python
- id: Integer, primary key
- name: String, unique (e.g., "llama3.3-70b")
- base_url: String
- api_key: String
- max_tokens: Integer, default=4096
- max_concurrent: Integer, default=2  # KEY: default is 2
- votes: Integer, default=1
- is_analyzer: Boolean, default=False
- is_verifier: Boolean, default=False
- analysis_prompt_template: Text
- verification_prompt_template: Text
```

### ScanConfig
```python
- id: Integer, primary key
- scan_id: Integer, ForeignKey("scans.id")
- analysis_mode: String, default="primary_verifiers"
- primary_analyzer_id: Integer, ForeignKey("model_configs.id"), nullable
- scope: String, default="full"
- scanner_concurrency: Integer, default=20
- verifier_concurrency: Integer, default=10
- enricher_concurrency: Integer, default=5
```

### ScanFile
```python
- id: Integer, primary key
- scan_id: Integer, ForeignKey("scans.id"), index=True
- file_path: String, index=True
- file_hash: String
- risk_level: String (high/normal/low)
- status: String, default="pending"
- created_at: DateTime, server_default=func.now()
- chunks: relationship to ScanFileChunk
```

### ScanFileChunk
```python
- id: Integer, primary key
- scan_file_id: Integer, ForeignKey("scan_files.id"), index=True
- chunk_index: Integer
- chunk_type: String (function/class/full_file)
- symbol_name: String, nullable
- start_line: Integer
- end_line: Integer
- content_hash: String, index=True
- status: String, default="pending"
- retry_count: Integer, default=0
- scan_file: relationship back to ScanFile
```

### Symbol
```python
- id: Integer, primary key
- scan_id: Integer, ForeignKey("scans.id"), index=True
- name: String, index=True
- qualified_name: String, index=True
- symbol_type: String (function/class/method/variable)
- file_path: String, index=True
- start_line: Integer
- end_line: Integer
- metadata: JSON (params, return_type, decorators, docstring)
```

### SymbolReference
```python
- id: Integer, primary key
- scan_id: Integer, ForeignKey("scans.id"), index=True
- symbol_id: Integer, ForeignKey("symbols.id"), index=True
- from_file: String
- from_line: Integer
- from_symbol_id: Integer, ForeignKey("symbols.id"), nullable
- reference_type: String (call/import/inherit)
```

### ImportRelation
```python
- id: Integer, primary key
- scan_id: Integer, ForeignKey("scans.id"), index=True
- importer_file: String, index=True
- imported_module: String
- imported_names: JSON
- resolved_file: String, nullable
```

### DraftFinding
```python
- id: Integer, primary key
- scan_id: Integer, ForeignKey("scans.id"), index=True
- chunk_id: Integer, ForeignKey("scan_file_chunks.id")
- title: String
- vulnerability_type: String
- severity: String
- line_number: Integer
- snippet: Text
- reason: Text
- auto_detected: Boolean, default=False
- status: String, default="pending"
- created_at: DateTime, server_default=func.now()
```

### VerifiedFinding
```python
- id: Integer, primary key
- draft_id: Integer, ForeignKey("draft_findings.id")
- scan_id: Integer, ForeignKey("scans.id"), index=True
- title: String
- confidence: Integer
- attack_vector: Text
- data_flow: Text
- adjusted_severity: String
- status: String, default="pending"
- created_at: DateTime, server_default=func.now()
```

## Also Update

Modify `backend/app/models/models.py` to add to Finding model:
- verified_id: Integer, ForeignKey("verified_findings.id")
- vulnerability_details: Text
- proof_of_concept: Text
- remediation_steps: Text
- references: Text
- cvss_score: Float

## Imports Needed

```python
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Float, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
```

## After Creation

Verify models by importing them and checking they can be instantiated.
