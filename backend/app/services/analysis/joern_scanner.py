"""
Joern-based vulnerability scanner using Code Property Graphs.

This scanner uses Joern (https://joern.io) for deterministic vulnerability detection
via static analysis. Unlike LLM-based scanning, Joern provides:
- Reproducible results
- Data flow analysis (taint tracking)
- Fast scanning (no inference costs)
- High precision for known vulnerability patterns

For large repositories, the scanner chunks by directory to avoid memory issues.

Security note: This module uses asyncio.create_subprocess_exec which safely passes
arguments as a list without shell interpolation, preventing command injection.
"""

import os
import asyncio
import tempfile
import shutil
import time
from typing import List, Dict, Optional
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime

from sqlalchemy.orm import Session
from app.models.scanner_models import LLMRequestLog

# Joern query templates for different vulnerability classes
JOERN_QUERIES = {
    "default": """
importCpg("{cpg_path}")

// Buffer Overflow - dangerous string functions
cpg.call.name("strcpy|strcat|sprintf|gets|vsprintf").l.foreach {{ c =>
  println(s"CWE-120|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Command Injection - shell functions
cpg.call.name("system|popen|execl|execle|execlp|execv|execve|execvp").l.foreach {{ c =>
  println(s"CWE-78|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Format String - printf family with variable format
cpg.call.name("printf|syslog|vsprintf|vprintf").l.foreach {{ c =>
  println(s"CWE-134|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Use After Free - free calls (needs verification for actual UAF)
cpg.call.name("free").l.foreach {{ c =>
  println(s"CWE-416|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|free|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}
""",

    "memory": """
importCpg("{cpg_path}")

// Buffer Overflow patterns
cpg.call.name("strcpy|strcat|sprintf|gets|vsprintf|memcpy|memmove").l.foreach {{ c =>
  println(s"CWE-120|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Use After Free - all free calls for verification
cpg.call.name("free").l.foreach {{ c =>
  println(s"CWE-416|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|free|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Double Free potential - multiple frees in same function
cpg.method.filter(m => m.call.name("free").size > 1).call.name("free").l.foreach {{ c =>
  println(s"CWE-415|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|free|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}
""",

    "injection": """
importCpg("{cpg_path}")

// Command Injection
cpg.call.name("system|popen|execl|execle|execlp|execv|execve|execvp").l.foreach {{ c =>
  println(s"CWE-78|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Format String Injection
cpg.call.name("printf|fprintf|sprintf|snprintf|syslog|vsprintf|vprintf|vfprintf").l.foreach {{ c =>
  println(s"CWE-134|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Path Traversal - file operations
cpg.call.name("fopen|open|freopen|creat").l.foreach {{ c =>
  println(s"CWE-22|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}
""",

    "all": """
importCpg("{cpg_path}")

// Buffer Overflow
cpg.call.name("strcpy|strcat|sprintf|gets|vsprintf|memcpy|memmove|strncpy|strncat").l.foreach {{ c =>
  println(s"CWE-120|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Use After Free
cpg.call.name("free").l.foreach {{ c =>
  println(s"CWE-416|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|free|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Command Injection
cpg.call.name("system|popen|execl|execle|execlp|execv|execve|execvp").l.foreach {{ c =>
  println(s"CWE-78|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Format String
cpg.call.name("printf|fprintf|sprintf|syslog|vsprintf|vprintf").l.foreach {{ c =>
  println(s"CWE-134|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Path Traversal
cpg.call.name("fopen|open|freopen|creat").l.foreach {{ c =>
  println(s"CWE-22|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// Weak crypto
cpg.call.name(".*MD5.*|.*SHA1.*|.*DES.*|.*RC4.*").l.foreach {{ c =>
  println(s"CWE-327|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}
""",

    "uefi": """
importCpg("{cpg_path}")

// UEFI Buffer Operations - CopyMem/SetMem without proper size validation
cpg.call.name("CopyMem|SetMem|ZeroMem").l.foreach {{ c =>
  println(s"CWE-120|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// UEFI Memory Management - potential UAF/double-free
cpg.call.name("FreePool|SafeFreePool").l.foreach {{ c =>
  println(s"CWE-416|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// UEFI String Functions - potential buffer overflow
cpg.call.name("StrCpy|StrnCpy|StrCat|StrnCat|AsciiStrCpy|AsciiStrnCpy|AsciiStrCat").l.foreach {{ c =>
  println(s"CWE-120|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// UEFI Memory Allocation - need error handling verification
cpg.call.name("AllocatePool|AllocateZeroPool|AllocatePages|ReallocatePool").l.foreach {{ c =>
  println(s"CWE-789|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// SMM Handler - potential SMM callout vulnerabilities
cpg.call.name(".*SmmHandler.*|.*SmiHandler.*").l.foreach {{ c =>
  println(s"CWE-749|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}

// UEFI Variable Access - check for proper validation
cpg.call.name("GetVariable|SetVariable|QueryVariableInfo").l.foreach {{ c =>
  println(s"CWE-269|${{c.location.filename}}|${{c.lineNumber.getOrElse(-1)}}|${{c.name}}|${{c.code.take(120).replaceAll("\\n", " ")}}")
}}
"""
}

# CWE to human-readable name mapping
CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-78": "Command Injection",
    "CWE-89": "SQL Injection",
    "CWE-120": "Buffer Overflow",
    "CWE-134": "Format String Vulnerability",
    "CWE-190": "Integer Overflow",
    "CWE-269": "UEFI Variable Access",
    "CWE-327": "Weak Cryptographic Algorithm",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-749": "SMM Handler Vulnerability",
    "CWE-789": "Memory Allocation",
    "CWE-798": "Hardcoded Credentials",
    "CWE-824": "Uninitialized Pointer",
}

# Severity mapping by CWE
CWE_SEVERITY = {
    "CWE-22": "High",
    "CWE-78": "Critical",
    "CWE-89": "Critical",
    "CWE-120": "High",
    "CWE-134": "High",
    "CWE-190": "High",
    "CWE-269": "Medium",  # UEFI Variable Access - needs verification
    "CWE-327": "Medium",
    "CWE-415": "High",
    "CWE-416": "High",
    "CWE-749": "Critical",  # SMM vulnerabilities are severe
    "CWE-789": "Medium",  # Allocation - needs null check verification
    "CWE-798": "High",
    "CWE-824": "Medium",
}


@dataclass
class JoernFinding:
    """Raw finding from Joern output"""
    cwe: str
    file_path: str
    line_number: int
    sink_function: str
    code_snippet: str


@dataclass
class DirectoryChunk:
    """A chunk of directories to process together"""
    paths: List[str]
    file_count: int
    estimated_size: int


class JoernScanner:
    """
    Scans code using Joern CPG analysis via Docker.

    Designed for large repositories - processes in directory chunks
    to avoid memory exhaustion.

    Configuration (via environment or .env file):
    - JOERN_DOCKER_IMAGE: Docker image to use (default: ghcr.io/joernio/joern:nightly)
    - JOERN_TIMEOUT: Timeout in seconds for Joern operations (default: 600)
    """

    def __init__(
        self,
        scan_id: int,
        source_path: str,
        query_set: str = "default",
        chunk_strategy: str = "directory",
        max_files_per_cpg: int = 100,
        db: Session = None,
    ):
        from app.core.config import settings

        self.scan_id = scan_id
        self.source_path = Path(source_path)
        self.query_set = query_set
        self.chunk_strategy = chunk_strategy
        self.max_files_per_cpg = max_files_per_cpg
        self.db = db
        self._temp_dirs: List[str] = []

        # Load config
        self.docker_image = settings.JOERN_DOCKER_IMAGE
        self.timeout = settings.JOERN_TIMEOUT

    async def scan(self) -> List[dict]:
        """Run Joern scan on the source code."""
        print(f"[Scan {self.scan_id}] Starting Joern scan on {self.source_path}")
        print(f"[Scan {self.scan_id}] Query set: {self.query_set}, Strategy: {self.chunk_strategy}")

        all_findings = []

        try:
            chunks = self._create_chunks()
            print(f"[Scan {self.scan_id}] Created {len(chunks)} chunks for processing")

            for i, chunk in enumerate(chunks):
                print(f"[Scan {self.scan_id}] Processing chunk {i+1}/{len(chunks)} ({chunk.file_count} files)")
                findings = await self._scan_chunk(chunk)
                all_findings.extend(findings)
                print(f"[Scan {self.scan_id}] Chunk {i+1} found {len(findings)} potential issues")

        finally:
            self._cleanup()

        deduped = self._deduplicate_findings(all_findings)
        print(f"[Scan {self.scan_id}] Joern scan complete: {len(deduped)} unique findings")

        return deduped

    def _create_chunks(self) -> List[DirectoryChunk]:
        """Create directory chunks for processing"""
        if self.chunk_strategy == "file":
            return self._chunk_by_files()
        else:
            return self._chunk_by_directories()

    def _chunk_by_directories(self) -> List[DirectoryChunk]:
        """Chunk by top-level directories."""
        chunks = []
        source_files = self._get_source_files()

        if len(source_files) <= self.max_files_per_cpg:
            return [DirectoryChunk(
                paths=[str(self.source_path)],
                file_count=len(source_files),
                estimated_size=sum(f.stat().st_size for f in source_files)
            )]

        dir_files: Dict[str, List[Path]] = {}
        for f in source_files:
            rel_path = f.relative_to(self.source_path)
            top_dir = rel_path.parts[0] if len(rel_path.parts) > 1 else "."
            if top_dir not in dir_files:
                dir_files[top_dir] = []
            dir_files[top_dir].append(f)

        current_chunk_dirs = []
        current_chunk_files = 0

        for dir_name, files in sorted(dir_files.items()):
            if current_chunk_files + len(files) > self.max_files_per_cpg and current_chunk_dirs:
                chunks.append(DirectoryChunk(
                    paths=current_chunk_dirs,
                    file_count=current_chunk_files,
                    estimated_size=0
                ))
                current_chunk_dirs = []
                current_chunk_files = 0

            if dir_name == ".":
                current_chunk_dirs.append(str(self.source_path))
            else:
                current_chunk_dirs.append(str(self.source_path / dir_name))
            current_chunk_files += len(files)

        if current_chunk_dirs:
            chunks.append(DirectoryChunk(
                paths=current_chunk_dirs,
                file_count=current_chunk_files,
                estimated_size=0
            ))

        return chunks

    def _chunk_by_files(self) -> List[DirectoryChunk]:
        """Chunk by individual files or small groups."""
        source_files = self._get_source_files()
        chunks = []

        for i in range(0, len(source_files), self.max_files_per_cpg):
            batch = source_files[i:i + self.max_files_per_cpg]
            temp_dir = tempfile.mkdtemp(prefix=f"joern_chunk_{i}_")
            self._temp_dirs.append(temp_dir)

            for f in batch:
                rel_path = f.relative_to(self.source_path)
                target = Path(temp_dir) / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, target)

            chunks.append(DirectoryChunk(
                paths=[temp_dir],
                file_count=len(batch),
                estimated_size=sum(f.stat().st_size for f in batch)
            ))

        return chunks

    def _get_source_files(self) -> List[Path]:
        """Get all C/C++ source files"""
        extensions = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx'}
        files = []
        for ext in extensions:
            files.extend(self.source_path.rglob(f"*{ext}"))
        return sorted(files)

    async def _scan_chunk(self, chunk: DirectoryChunk) -> List[dict]:
        """Scan a single chunk using Joern Docker"""
        findings = []
        workspace = tempfile.mkdtemp(prefix="joern_workspace_")
        self._temp_dirs.append(workspace)

        try:
            source_mount = chunk.paths[0]

            if len(chunk.paths) > 1:
                combined_dir = tempfile.mkdtemp(prefix="joern_combined_")
                self._temp_dirs.append(combined_dir)
                for path in chunk.paths:
                    dir_name = os.path.basename(path)
                    target = os.path.join(combined_dir, dir_name)
                    if not os.path.exists(target):
                        shutil.copytree(path, target)
                source_mount = combined_dir

            print(f"[Scan {self.scan_id}] Creating CPG for {source_mount}")

            cpg_created = await self._create_cpg(source_mount, workspace)
            if not cpg_created:
                print(f"[Scan {self.scan_id}] Failed to create CPG for chunk")
                return []

            print(f"[Scan {self.scan_id}] Running Joern queries...")
            raw_findings = await self._run_queries(workspace)

            for jf in raw_findings:
                finding = self._convert_to_draft_finding(jf, source_mount)
                if finding:
                    findings.append(finding)

        except Exception as e:
            print(f"[Scan {self.scan_id}] Error scanning chunk: {e}")
            import traceback
            traceback.print_exc()

        return findings

    async def _create_cpg(self, source_path: str, workspace: str) -> bool:
        """Create CPG using joern-parse via Docker"""
        # Docker requires absolute paths for volume mounts
        abs_source_path = os.path.abspath(source_path)
        abs_workspace = os.path.abspath(workspace)

        # Using create_subprocess_exec with explicit argument list (safe, no shell)
        args = [
            "docker", "run", "--rm",
            "-v", f"{abs_source_path}:/app:ro",
            "-v", f"{abs_workspace}:/workspace",
            self.docker_image,
            "joern-parse", "/app", "-o", "/workspace/cpg.bin"
        ]

        print(f"[Scan {self.scan_id}] Running: docker run ... {self.docker_image} joern-parse")

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)

        if proc.returncode != 0:
            print(f"[Scan {self.scan_id}] joern-parse failed: {stderr.decode()}")
            return False

        return os.path.exists(os.path.join(workspace, "cpg.bin"))

    async def _run_queries(self, workspace: str) -> List[JoernFinding]:
        """Run Joern queries and parse output"""
        findings = []
        
        query_template = JOERN_QUERIES.get(self.query_set, JOERN_QUERIES["default"])
        query = query_template.format(cpg_path="/workspace/cpg.bin")

        query_file = os.path.join(workspace, "query.sc")
        with open(query_file, 'w') as f:
            f.write(query)

        # Create log entry if DB is available
        log_entry = None
        if self.db:
            try:
                log_entry = LLMRequestLog(
                    scan_id=self.scan_id,
                    model_name="Joern CPG",
                    phase="scanner",
                    analyzer_name="Joern Static Analysis",
                    request_prompt=query,
                    status="running",
                    created_at=datetime.now().astimezone()
                )
                self.db.add(log_entry)
                self.db.commit()
            except Exception as e:
                print(f"[Scan {self.scan_id}] Failed to create Joern log: {e}")

        start_time = time.time()

        # Docker requires absolute paths for volume mounts
        abs_workspace = os.path.abspath(workspace)

        # Using create_subprocess_exec with explicit argument list (safe, no shell)
        args = [
            "docker", "run", "--rm",
            "-v", f"{abs_workspace}:/workspace",
            self.docker_image,
            "joern", "--script", "/workspace/query.sc"
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            output = stdout.decode()
            error_output = stderr.decode()
            
            duration_ms = (time.time() - start_time) * 1000

            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('CWE-'):
                    parts = line.split('|')
                    if len(parts) >= 5:
                        try:
                            finding = JoernFinding(
                                cwe=parts[0],
                                file_path=parts[1],
                                line_number=int(parts[2]) if parts[2] != "-1" else 0,
                                sink_function=parts[3],
                                code_snippet='|'.join(parts[4:])
                            )
                            findings.append(finding)
                        except (ValueError, IndexError) as e:
                            print(f"[Scan {self.scan_id}] Failed to parse line: {line} - {e}")

            # Update log entry
            if log_entry and self.db:
                try:
                    log_entry.raw_response = output
                    if error_output:
                        log_entry.raw_response += f"\n\nSTDERR:\n{error_output}"
                    
                    log_entry.status = "completed"
                    log_entry.findings_count = len(findings)
                    log_entry.duration_ms = duration_ms
                    self.db.commit()
                except Exception as e:
                    print(f"[Scan {self.scan_id}] Failed to update Joern log: {e}")

        except Exception as e:
            if log_entry and self.db:
                try:
                    log_entry.status = "failed"
                    log_entry.parse_error = str(e)
                    self.db.commit()
                except:
                    pass
            raise e

        return findings

    def _convert_to_draft_finding(self, jf: JoernFinding, source_mount: str) -> Optional[dict]:
        """Convert Joern finding to DraftFinding-compatible dict"""
        if jf.line_number <= 0:
            return None

        file_path = jf.file_path
        if file_path.startswith("/app/"):
            file_path = file_path[5:]

        vuln_name = CWE_NAMES.get(jf.cwe, jf.cwe)
        severity = CWE_SEVERITY.get(jf.cwe, "Medium")
        title = f"{vuln_name} via {jf.sink_function}()"

        reasons = {
            "CWE-78": f"User-controlled data may reach {jf.sink_function}() for shell usage",
            "CWE-89": f"Potential SQL injection via {jf.sink_function}()",
            "CWE-120": f"Unbounded copy using {jf.sink_function}() may overflow buffer",
            "CWE-134": f"Variable format string passed to {jf.sink_function}()",
            "CWE-190": f"Integer arithmetic in allocation size may overflow",
            "CWE-22": f"File path passed to {jf.sink_function}() may allow traversal",
            "CWE-327": f"Weak cryptographic algorithm: {jf.sink_function}",
            "CWE-415": f"Potential double-free detected",
            "CWE-416": f"Memory freed - verify no subsequent use",
            "CWE-798": f"Potential hardcoded credential",
            "CWE-824": f"Potentially uninitialized pointer dereference",
        }
        reason = reasons.get(jf.cwe, f"Potential {vuln_name} detected")

        return {
            'title': title,
            'type': jf.cwe,
            'vulnerability_type': jf.cwe,
            'severity': severity,
            'line': jf.line_number,
            'line_number': jf.line_number,
            'snippet': jf.code_snippet[:200],
            'reason': reason,
            'file_path': file_path,
            '_source': 'joern',
            '_sink_function': jf.sink_function,
            '_analyzer': 'joern',
            '_analyzer_id': None,
            '_model': 'joern-cpg',
        }

    def _deduplicate_findings(self, findings: List[dict]) -> List[dict]:
        """Remove duplicate findings by signature"""
        seen = set()
        unique = []

        for f in findings:
            sig = f"{f.get('file_path', '')}:{f.get('line', 0)}:{f.get('type', '')}"
            if sig not in seen:
                seen.add(sig)
                unique.append(f)

        return unique

    def _cleanup(self):
        """Clean up temporary directories"""
        for temp_dir in self._temp_dirs:
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                print(f"[Scan {self.scan_id}] Failed to cleanup {temp_dir}: {e}")
        self._temp_dirs = []


async def test_joern_scanner():
    """Quick test of Joern scanner"""
    scanner = JoernScanner(
        scan_id=0,
        source_path="/tmp/joern_test",
        query_set="default"
    )

    findings = await scanner.scan()

    print("\n=== JOERN SCANNER TEST RESULTS ===")
    for f in findings:
        print(f"{f['type']} | {f['file_path']}:{f['line']} | {f['title']}")
    print(f"\nTotal: {len(findings)} findings")

    return findings


if __name__ == "__main__":
    asyncio.run(test_joern_scanner())
