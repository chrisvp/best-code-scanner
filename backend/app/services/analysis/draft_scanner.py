from typing import List, Dict, Optional
import os
import asyncio
import fnmatch

from app.models.scanner_models import ScanFileChunk, ScanFile, ScanProfile, ProfileAnalyzer
from app.services.analysis.static_detector import StaticPatternDetector
from app.services.analysis.parsers import DraftParser
from app.services.orchestration.cache import AnalysisCache
from app.services.orchestration.model_orchestrator import ModelPool, ModelOrchestrator
from app.core.database import SessionLocal


class ProfileAwareScanner:
    """Scans chunks using profile-defined analyzers with custom prompts and filters"""

    def __init__(self, scan_id: int, profile: ScanProfile, orchestrator: ModelOrchestrator,
                 cache: AnalysisCache, static_detector: StaticPatternDetector = None):
        self.scan_id = scan_id
        self.profile = profile
        self.orchestrator = orchestrator
        self.cache = cache
        self.static_detector = static_detector if static_detector else StaticPatternDetector()
        self.parser = DraftParser()

    def _format_code_with_lines(self, code: str, start_line: int) -> str:
        """Prefix lines with numbers for LLM reference"""
        lines = code.split('\n')
        return '\n'.join(f"{start_line + i:4d} | {line}" for i, line in enumerate(lines))

    def _matches_filter(self, file_path: str, language: str, analyzer: ProfileAnalyzer) -> bool:
        """Check if a file matches the analyzer's filters"""
        # Check file filter (glob pattern like "*.c,*.h")
        if analyzer.file_filter:
            filename = os.path.basename(file_path)
            patterns = [p.strip() for p in analyzer.file_filter.split(',')]
            if not any(fnmatch.fnmatch(filename, p) for p in patterns):
                return False

        # Check language filter
        if analyzer.language_filter:
            if language.lower() not in [l.lower() for l in analyzer.language_filter]:
                return False

        return True

    def _validate_finding(self, finding: dict, chunk: ScanFileChunk) -> bool:
        """Validate finding against chunk bounds"""
        try:
            if not finding.get('title'):
                return False

            line = int(finding.get('line', finding.get('line_number', 0)))

            if line <= 0:
                return False

            margin = 5
            if line < (chunk.start_line - margin) or line > (chunk.end_line + margin):
                return False

            return True
        except (ValueError, TypeError):
            return False

    async def scan_batch_with_profile(self, chunks: List[ScanFileChunk]) -> Dict[int, List[dict]]:
        """
        Scan chunks using all enabled analyzers from the profile.
        Each analyzer can have its own prompt template and file filters.
        Returns dict mapping chunk_id to aggregated findings from all analyzers.
        """
        results = {chunk.id: [] for chunk in chunks}

        # Get enabled analyzers ordered by run_order
        analyzers = [a for a in self.profile.analyzers if a.enabled and a.role == 'analyzer']
        if not analyzers:
            return results

        db = SessionLocal()
        try:
            # Pre-fetch file info for all chunks
            chunk_info = {}
            for chunk in chunks:
                scan_file = db.query(ScanFile).filter(ScanFile.id == chunk.scan_file_id).first()
                if not scan_file:
                    continue

                try:
                    with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    content = ''.join(lines[chunk.start_line - 1:chunk.end_line])
                except Exception as e:
                    print(f"Error reading file {scan_file.file_path}: {e}")
                    continue

                ext = os.path.splitext(scan_file.file_path)[1]
                language = ext.lstrip('.')

                chunk_info[chunk.id] = {
                    'chunk': chunk,
                    'scan_file': scan_file,
                    'content': content,
                    'language': language,
                    'content_hash': AnalysisCache.hash_content(content),
                    'formatted_code': self._format_code_with_lines(content, chunk.start_line),
                    'file_name': os.path.basename(scan_file.file_path),
                    'file_list': self._get_codebase_files(db, chunk),
                    'full_file': self._get_full_file_context(scan_file, chunk)
                }

            # Run each analyzer in order
            for analyzer in analyzers:
                # Get model pool for this analyzer (or use default)
                if analyzer.model_id:
                    pool = self.orchestrator.get_pool(analyzer.model.name) if analyzer.model else None
                else:
                    pool = self.orchestrator.get_primary_analyzer()

                if not pool:
                    print(f"No model available for analyzer: {analyzer.name}")
                    continue

                # Filter chunks that match this analyzer's file/language filters
                matching_chunks = []
                for chunk_id, info in chunk_info.items():
                    if self._matches_filter(info['scan_file'].file_path, info['language'], analyzer):
                        # Check cache first
                        cache_key = f"{info['content_hash']}:{analyzer.id}"
                        cached = self.cache.get_analysis(cache_key)
                        if cached is not None:
                            results[chunk_id].extend(cached)
                        else:
                            matching_chunks.append((chunk_id, info))

                if not matching_chunks:
                    continue

                print(f"[Scan {self.scan_id}] Running analyzer '{analyzer.name}' on {len(matching_chunks)} chunks")

                # Build prompts for this analyzer
                prompts = []
                prompt_chunk_ids = []
                for chunk_id, info in matching_chunks:
                    try:
                        prompt = analyzer.prompt_template.format(
                            code=info['formatted_code'],
                            language=info['language'],
                            file_name=info['file_name'],
                            file_path=info['scan_file'].file_path,
                            file_list=info['file_list'],
                            full_file=info['full_file']
                        )
                    except KeyError:
                        # Fallback for templates with missing placeholders
                        prompt = analyzer.prompt_template.format(
                            code=info['formatted_code'],
                            language=info['language'],
                            file_path=info['scan_file'].file_path
                        )
                    prompts.append(prompt)
                    prompt_chunk_ids.append(chunk_id)

                # Call model
                try:
                    responses = await pool.call_batch(prompts)

                    for i, (chunk_id, info) in enumerate(matching_chunks):
                        response = responses[i] if i < len(responses) else ""
                        findings = self.parser.parse(response) or []

                        # Debug: Print response summary (after thinking tags stripped by parser)
                        import re
                        stripped_response = re.sub(r'<thinking>.*?</thinking>', '', response, flags=re.DOTALL | re.IGNORECASE)
                        stripped_response = stripped_response.strip()
                        print(f"[DEBUG] Analyzer '{analyzer.name}' chunk {chunk_id}: response_len={len(response)}, stripped_len={len(stripped_response)}, findings_count={len(findings)}")
                        if len(stripped_response) < 500:
                            print(f"[DEBUG] Stripped response: {stripped_response}")
                        elif not findings:
                            print(f"[DEBUG] Stripped preview: {stripped_response[:300]}...")

                        # Validate and annotate findings
                        valid_findings = []
                        chunk = info['chunk']
                        for f in findings:
                            if self._validate_finding(f, chunk):
                                f['_analyzer'] = analyzer.name
                                f['_model'] = pool.config.name
                                valid_findings.append(f)

                        results[chunk_id].extend(valid_findings)

                        # Cache results
                        cache_key = f"{info['content_hash']}:{analyzer.id}"
                        self.cache.set_analysis(cache_key, valid_findings)

                except Exception as e:
                    print(f"Analyzer {analyzer.name} failed: {e}")

                # Check stop_on_findings flag
                if analyzer.stop_on_findings:
                    has_findings = any(len(results[cid]) > 0 for cid, _ in matching_chunks)
                    if has_findings:
                        print(f"[Scan {self.scan_id}] Stopping after analyzer '{analyzer.name}' found issues")
                        break

        finally:
            db.close()

        return results

    def _get_codebase_files(self, db, chunk: ScanFileChunk) -> str:
        """Get list of all files in the codebase for context"""
        scan_file = db.query(ScanFile).filter(ScanFile.id == chunk.scan_file_id).first()
        if not scan_file:
            return "(No files found)"

        all_files = db.query(ScanFile).filter(
            ScanFile.scan_id == scan_file.scan_id
        ).all()

        file_names = [os.path.basename(f.file_path) for f in all_files]
        if len(file_names) <= 15:
            return "\n".join(f"- {name}" for name in file_names)
        else:
            return "\n".join(f"- {name}" for name in file_names[:15]) + f"\n... and {len(file_names) - 15} more files"

    def _get_full_file_context(self, scan_file: ScanFile, chunk: ScanFileChunk) -> str:
        """Get the full file content with the analyzed chunk highlighted"""
        try:
            with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_content = f.read()

            lines = file_content.split('\n')

            if len(lines) > 300:
                start = max(0, chunk.start_line - 50)
                end = min(len(lines), chunk.end_line + 50)
                result = [f"(Showing lines {start+1}-{end} of {len(lines)} - full file too large)"]
                for i in range(start, end):
                    prefix = ">>>" if chunk.start_line - 1 <= i < chunk.end_line else "   "
                    result.append(f"{prefix} {i+1}: {lines[i]}")
                return "\n".join(result)
            else:
                result = []
                for i, line in enumerate(lines):
                    prefix = ">>>" if chunk.start_line - 1 <= i < chunk.end_line else "   "
                    result.append(f"{prefix} {i+1}: {line}")
                return "\n".join(result)
        except Exception as e:
            return f"(Error reading full file: {e})"


class DraftScanner:
    """Scans chunks for draft findings with multi-model voting support"""

    SCAN_PROMPT = """Analyze this {language} code for security vulnerabilities.

=== FILE BEING ANALYZED ===
{file_name}

=== CODE TO ANALYZE (with line numbers) ===
{code}

=== OTHER FILES IN CODEBASE ===
{file_list}

=== FULL FILE CONTEXT ===
{full_file}

Code has line numbers (e.g., "  42 | code"). Use EXACT line numbers in findings.

=== CWE CLASSIFICATION RULES ===
Use the CORRECT CWE based on the SINK, not the intermediate functions:

| Sink Pattern | CWE | Name |
|--------------|-----|------|
| system(), popen(), exec*() with user data | CWE-78 | Command Injection |
| strcpy(), strcat(), sprintf(), gets() to fixed buffer | CWE-120 | Buffer Overflow |
| printf(user_data) - user string AS format | CWE-134 | Format String |
| free(ptr) then use ptr, or free twice | CWE-416/415 | Use-After-Free/Double-Free |
| SQL query with concatenated user input | CWE-89 | SQL Injection |
| file path with "../" or user-controlled path | CWE-22 | Path Traversal |
| size_t/int overflow in malloc size or loop | CWE-190 | Integer Overflow |
| hardcoded password, key, token in source | CWE-798 | Hardcoded Credentials |

=== CRITICAL CLASSIFICATION RULES ===
- If sprintf/snprintf builds a string that is THEN passed to system()/popen()/exec() → CWE-78 Command Injection
- CWE-134 Format String is ONLY when user input IS the format string (e.g., printf(user_data))
- sprintf(buf, "%s", user_data) is NOT format string - the format IS fixed ("%s")
- LOOK AT THE SINK (system/printf/strcpy), not the intermediate functions

=== WHAT TO REPORT ===
- Memory corruption: buffer overflow, use-after-free, double-free
- Injection: command, SQL, format string, path traversal
- Crypto issues: hardcoded secrets, weak algorithms
- Integer issues: overflow in size calculations

=== WHAT TO SKIP ===
- Missing null checks (unless causes crash with untrusted input)
- Style issues, missing error handling
- Theoretical issues requiring unlikely conditions

=== EXAMPLES ===

 331 | strcpy(credentials, username);
 332 | strcat(credentials, password);

*DRAFT: Buffer Overflow in Credential Handling
*TYPE: CWE-120
*SEVERITY: High
*LINE: 331
*SNIPPET: strcpy(credentials, username);
*REASON: Unbounded copy of username into fixed 128-byte buffer
*END_DRAFT

 330 | snprintf(cmd, sizeof(cmd), "/bin/sh %s", user_input);
 331 | system(cmd);

*DRAFT: Command Injection via Shell Execution
*TYPE: CWE-78
*SEVERITY: Critical
*LINE: 331
*SNIPPET: system(cmd);
*REASON: User-controlled input passed to system() shell execution
*END_DRAFT

 410 | free(block);
 411 | process_data(block->data);

*DRAFT: Use-After-Free
*TYPE: CWE-416
*SEVERITY: High
*LINE: 411
*SNIPPET: process_data(block->data);
*REASON: Accessing block->data after block was freed
*END_DRAFT

 312 | log_message(user_input);  // where log_message calls printf(msg)

*DRAFT: Format String Vulnerability
*TYPE: CWE-134
*SEVERITY: High
*LINE: 312
*SNIPPET: log_message(user_input);
*REASON: User input passed as format string to printf-family function
*END_DRAFT

=== OUTPUT FORMAT ===
*DRAFT: descriptive title
*TYPE: CWE-XXX
*SEVERITY: Critical/High/Medium/Low
*LINE: exact line number
*SNIPPET: the vulnerable code
*REASON: one sentence explanation
*END_DRAFT

Report all findings. If none found: *DRAFT:NONE"""

    def __init__(self, scan_id: int, model_pools: List[ModelPool], cache: AnalysisCache, static_detector: StaticPatternDetector = None):
        """
        Initialize scanner with multiple model pools for voting.

        Args:
            scan_id: The scan ID
            model_pools: List of model pools to use for voting (minimum 1)
            cache: Analysis cache for deduplication
            static_detector: Optional pre-loaded detector with rules from database
        """
        self.scan_id = scan_id
        self.model_pools = model_pools if isinstance(model_pools, list) else [model_pools]
        self.cache = cache
        # Use provided detector or create one with default rules
        self.static_detector = static_detector if static_detector else StaticPatternDetector()
        self.parser = DraftParser()

    def _format_code_with_lines(self, code: str, start_line: int) -> str:
        """Prefix lines with numbers for LLM reference"""
        lines = code.split('\n')
        return '\n'.join(f"{start_line + i:4d} | {line}" for i, line in enumerate(lines))

    def _validate_finding(self, finding: dict, chunk: ScanFileChunk) -> bool:
        """Validate finding against chunk bounds"""
        try:
            if not finding.get('title'):
                return False

            line = int(finding.get('line', finding.get('line_number', 0)))
            
            # Must be non-zero
            if line <= 0:
                return False
                
            # Must be within chunk bounds (with small margin for context lines)
            margin = 5
            if line < (chunk.start_line - margin) or line > (chunk.end_line + margin):
                return False
                
            return True
        except (ValueError, TypeError):
            return False

    async def scan_batch(self, chunks: List[ScanFileChunk]) -> Dict[int, List[dict]]:
        """
        Scan multiple chunks using multi-model voting.
        Returns dict mapping chunk_id to list of findings.
        """
        results = {}
        to_llm = []
        to_llm_meta = []
        
        db = SessionLocal()
        try:
            for chunk in chunks:
                # Get File Info (needed for content and risk check)
                scan_file = db.query(ScanFile).filter(ScanFile.id == chunk.scan_file_id).first()
                if not scan_file:
                    continue
                    
                # Get Content
                try:
                    with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    content = ''.join(lines[chunk.start_line - 1:chunk.end_line])
                except Exception as e:
                    print(f"Error reading file {scan_file.file_path}: {e}")
                    continue

                content_hash = AnalysisCache.hash_content(content)

                # Check cache first
                cached = self.cache.get_analysis(content_hash)
                if cached is not None:
                    results[chunk.id] = cached
                    continue

                # Get language for static detection
                ext = os.path.splitext(scan_file.file_path)[1]
                language = ext.lstrip('.')

                # Run static detection
                static_findings, needs_llm = self.static_detector.scan_fast(chunk, language, content=content)
                
                # Force LLM for High Risk files
                if scan_file.risk_level == 'high':
                    needs_llm = True

                if not needs_llm:
                    # No interesting patterns - just return static findings
                    results[chunk.id] = static_findings
                    self.cache.set_analysis(content_hash, static_findings)
                    continue

                # Queue for LLM analysis with line numbers
                formatted_code = self._format_code_with_lines(content, chunk.start_line)

                # Pre-fetch context: file list and full file content
                file_list = self._get_codebase_files(db, chunk)
                full_file_content = self._get_full_file_context(scan_file, chunk)

                # Store code snippet and context to be formatted per-model later
                to_llm.append({
                    'code': formatted_code,
                    'language': language,
                    'file_name': os.path.basename(scan_file.file_path),
                    'file_list': file_list,
                    'full_file': full_file_content
                })
                to_llm_meta.append((chunk.id, content_hash, static_findings, chunk))
                    
        finally:
            db.close()

        # Multi-model batch LLM calls
        if to_llm:
            try:
                # Send to all models in parallel
                async def get_model_responses(pool: ModelPool):
                    try:
                        # Use custom prompt if configured, else default
                        template = pool.config.analysis_prompt_template or self.SCAN_PROMPT
                        
                        # Generate prompts specific to this model
                        model_prompts = []
                        for item in to_llm:
                            # Chunker already handles size limits - don't truncate here
                            # (was: item['code'] = item['code'][:8000] which cut off code)
                            # Default language if missing in template
                            try:
                                model_prompts.append(template.format(**item))
                            except KeyError:
                                # Fallback if template doesn't use {language}
                                model_prompts.append(template.format(code=item['code']))
                        
                        responses = await pool.call_batch(model_prompts)
                        return (pool.config.name, responses)
                    except Exception as e:
                        print(f"Model {pool.config.name} failed: {e}")
                        return (pool.config.name, ["" for _ in to_llm])

                model_tasks = [get_model_responses(pool) for pool in self.model_pools]
                all_model_results = await asyncio.gather(*model_tasks)

                # Process each chunk's responses from all models
                for idx, (chunk_id, content_hash, static_findings, chunk) in enumerate(to_llm_meta):
                    # Collect findings from each model
                    model_findings = []
                    for model_name, responses in all_model_results:
                        response = responses[idx] if idx < len(responses) else ""
                        findings = self.parser.parse(response)
                        if findings is None:
                            findings = await self._try_correction(response)
                        
                        if findings:
                            valid_findings = []
                            for f in findings:
                                if self._validate_finding(f, chunk):
                                    f['_model'] = model_name
                                    valid_findings.append(f)
                                else:
                                    print(f"Skipping invalid finding: {f.get('title')} at line {f.get('line')}")
                            
                            if valid_findings:
                                model_findings.append((model_name, valid_findings))

                    # Aggregate findings using voting
                    voted_findings = self._aggregate_findings(model_findings)
                    all_findings = static_findings + voted_findings
                    results[chunk_id] = all_findings
                    self.cache.set_analysis(content_hash, all_findings)

            except Exception as e:
                print(f"Multi-model scan failed: {e}")
                # Return static findings for all
                for chunk_id, content_hash, static_findings, chunk in to_llm_meta:
                    results[chunk_id] = static_findings
                    self.cache.set_analysis(content_hash, static_findings)

        return results

    def _aggregate_findings(self, model_findings: List[tuple]) -> List[dict]:
        """
        Aggregate findings from multiple models using voting.
        A finding is included if it appears in majority of models (2+ out of 3).
        Similar findings are merged based on line number and type.
        """
        if not model_findings:
            return []

        num_models = len(self.model_pools)

        # If only one model, add _models tracking and return
        if num_models == 1:
            if not model_findings:
                return []
            model_name, findings = model_findings[0]
            # Add _models list for consistency with multi-model path
            for f in findings:
                f['_votes'] = 1
                f['_models'] = [model_name]
            return findings

        # Group findings by signature (line + type)
        finding_votes = {}  # signature -> {finding, votes, models}

        for model_name, findings in model_findings:
            for f in findings:
                # Create signature for matching
                sig = self._finding_signature(f)

                if sig not in finding_votes:
                    finding_votes[sig] = {
                        'finding': f,
                        'votes': 0,
                        'models': [],
                        'severities': []
                    }

                finding_votes[sig]['votes'] += 1
                finding_votes[sig]['models'].append(model_name)
                finding_votes[sig]['severities'].append(f.get('severity', 'Medium'))

        # Filter by vote threshold (at least 1 model must report)
        # Lower threshold to catch more findings - verifiers will filter
        threshold = 0.5  # Any model can report (was num_models / 2)
        voted_findings = []

        for sig, data in finding_votes.items():
            if data['votes'] >= threshold:
                finding = data['finding'].copy()
                # Use most common severity
                finding['severity'] = max(set(data['severities']), key=data['severities'].count)
                # Add voting metadata
                finding['_votes'] = data['votes']
                finding['_models'] = data['models']
                voted_findings.append(finding)

        return voted_findings

    def _finding_signature(self, finding: dict) -> str:
        """Create a signature for matching similar findings across models."""
        line = finding.get('line', finding.get('line_number', 0))
        vuln_type = finding.get('type', finding.get('vulnerability_type', '')).lower()
        # Normalize common type variations
        vuln_type = vuln_type.replace(' ', '_').replace('-', '_')
        return f"{line}:{vuln_type}"

    async def _try_correction(self, response: str) -> List[dict]:
        """Try to correct a malformed response"""
        correction_prompt = f"""The previous response did not follow the required format.
Please reformat any findings to match exactly:

*DRAFT: title
*TYPE: vulnerability type
*SEVERITY: Critical/High/Medium/Low
*LINE: number
*SNIPPET: code
*REASON: explanation
*END_DRAFT

Or *DRAFT:NONE if no findings.

Previous response:
{response[:2000]}"""

        try:
            # Use first model pool for correction
            corrected = await self.model_pools[0].call(correction_prompt)
            return self.parser.parse(corrected) or []
        except Exception:
            return []

    def _get_chunk_content(self, chunk: ScanFileChunk) -> str:
        """Get the actual content of a chunk"""
        db = SessionLocal()
        try:
            scan_file = db.query(ScanFile).filter(
                ScanFile.id == chunk.scan_file_id
            ).first()

            if not scan_file:
                return ""

            with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            return ''.join(lines[chunk.start_line - 1:chunk.end_line])
        except Exception as e:
            print(f"Error reading chunk content: {e}")
            return ""
        finally:
            db.close()

    def _get_language(self, chunk: ScanFileChunk) -> str:
        """Get the language/extension for a chunk"""
        db = SessionLocal()
        try:
            scan_file = db.query(ScanFile).filter(
                ScanFile.id == chunk.scan_file_id
            ).first()

            if scan_file:
                ext = os.path.splitext(scan_file.file_path)[1]
                return ext.lstrip('.')

            return 'unknown'
        finally:
            db.close()

    def _get_codebase_files(self, db, chunk: ScanFileChunk) -> str:
        """Get list of all files in the codebase for context"""
        scan_file = db.query(ScanFile).filter(ScanFile.id == chunk.scan_file_id).first()
        if not scan_file:
            return "(No files found)"

        # Get all files in this scan
        all_files = db.query(ScanFile).filter(
            ScanFile.scan_id == scan_file.scan_id
        ).all()

        file_names = [os.path.basename(f.file_path) for f in all_files]
        if len(file_names) <= 15:
            return "\n".join(f"- {name}" for name in file_names)
        else:
            return "\n".join(f"- {name}" for name in file_names[:15]) + f"\n... and {len(file_names) - 15} more files"

    def _get_full_file_context(self, scan_file: ScanFile, chunk: ScanFileChunk) -> str:
        """Get the full file content with the analyzed chunk highlighted"""
        try:
            with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_content = f.read()

            lines = file_content.split('\n')

            # If file is very large, show surrounding context only
            if len(lines) > 300:
                start = max(0, chunk.start_line - 50)
                end = min(len(lines), chunk.end_line + 50)
                result = [f"(Showing lines {start+1}-{end} of {len(lines)} - full file too large)"]
                for i in range(start, end):
                    prefix = ">>>" if chunk.start_line - 1 <= i < chunk.end_line else "   "
                    result.append(f"{prefix} {i+1}: {lines[i]}")
                return "\n".join(result)
            else:
                result = []
                for i, line in enumerate(lines):
                    prefix = ">>>" if chunk.start_line - 1 <= i < chunk.end_line else "   "
                    result.append(f"{prefix} {i+1}: {line}")
                return "\n".join(result)
        except Exception as e:
            return f"(Error reading full file: {e})"
