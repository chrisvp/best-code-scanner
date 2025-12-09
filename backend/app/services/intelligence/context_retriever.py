import os
import re
from typing import List, Optional, Dict, Tuple
from sqlalchemy.orm import Session

from app.models.scanner_models import Symbol, SymbolReference, ImportRelation, ScanFileChunk, ScanFile


class ContextRetriever:
    """Retrieves relevant code context for analysis - Claude Code style deep context"""

    def __init__(self, scan_id: int, db: Session):
        self.scan_id = scan_id
        self.db = db
        self._app_type_cache = None
        self._entry_points_cache = None

    async def get_context(self, chunk: ScanFileChunk, max_tokens: int = 8000) -> str:
        """
        Get deep context for analyzing a chunk - pre-fetched spoon-fed style.
        Returns formatted context string with full file content, callers, and codebase structure.
        """
        sections = []

        # Get scan file and chunk content
        scan_file = self.db.query(ScanFile).filter(
            ScanFile.id == chunk.scan_file_id
        ).first()

        chunk_content = self._get_chunk_content(chunk)

        # 1. FULL file content (this is key - model sees the vulnerable code in context)
        if scan_file:
            sections.append(f"=== FULL FILE: {os.path.basename(scan_file.file_path)} ===")
            try:
                with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_content = f.read()
                # If file is huge, show context around the chunk
                if len(file_content) > 15000:
                    lines = file_content.split('\n')
                    start = max(0, chunk.start_line - 100)
                    end = min(len(lines), chunk.end_line + 100)
                    sections.append(f"(Showing lines {start+1}-{end} of {len(lines)})")
                    for i in range(start, end):
                        prefix = ">>> " if chunk.start_line - 1 <= i < chunk.end_line else "    "
                        sections.append(f"{prefix}{i+1}: {lines[i]}")
                else:
                    lines = file_content.split('\n')
                    for i, line in enumerate(lines):
                        prefix = ">>> " if chunk.start_line - 1 <= i < chunk.end_line else "    "
                        sections.append(f"{prefix}{i+1}: {line}")
            except Exception as e:
                sections.append(f"(Error reading file: {e})")
            sections.append("")

        # 3. Application Type Detection
        app_type = self._detect_application_type()
        sections.append("=== APPLICATION CONTEXT ===")
        sections.append(f"Type: {app_type['type']}")
        sections.append(f"Threat Model: {app_type['threat_model']}")
        sections.append("")

        # 4. Entry Points Analysis
        entry_points = self._find_entry_points()
        if entry_points:
            sections.append("=== ENTRY POINTS (where external input enters) ===")
            for ep in entry_points[:5]:
                sections.append(f"- {ep['name']} in {ep['file']}:{ep['line']} ({ep['type']})")
            sections.append("")

        # 3. Full File Context (surrounding code)
        if scan_file:
            file_context = self._get_file_context(scan_file, chunk)
            if file_context:
                sections.append("=== FILE CONTEXT (surrounding code) ===")
                sections.append(file_context)
                sections.append("")

        # 4. Functions defined in this chunk
        chunk_functions = self._extract_function_names(chunk_content)

        # 5. Call Chain Analysis - trace from entry points to vulnerable code
        if chunk_functions:
            call_chain = self._trace_call_chain_to_entry(chunk_functions)
            if call_chain:
                sections.append("=== CALL CHAIN FROM ENTRY POINTS ===")
                for chain in call_chain[:3]:
                    sections.append(f"Path: {' -> '.join(chain['path'])}")
                    if chain.get('entry_type'):
                        sections.append(f"  Input source: {chain['entry_type']}")
                sections.append("")

        # 6. Callers of vulnerable functions (with code)
        if chunk_functions:
            callers_section = []
            for func_name in chunk_functions[:3]:
                callers = self._find_callers(func_name)
                for caller in callers[:3]:
                    code = self._get_symbol_code(caller)
                    if code:
                        callers_section.append(f"# {caller.qualified_name} ({caller.file_path}:{caller.start_line})")
                        callers_section.append(code)
                        callers_section.append("")

            if callers_section:
                sections.append("=== FUNCTIONS THAT CALL THIS CODE ===")
                sections.extend(callers_section)

        # 7. Data source analysis for function parameters
        data_sources = self._analyze_data_sources(chunk_content)
        if data_sources:
            sections.append("=== DATA SOURCES (where inputs come from) ===")
            for ds in data_sources:
                sections.append(f"- {ds['param']}: {ds['source']} ({ds['risk']})")
            sections.append("")

        # 8. Called function definitions
        calls = self._extract_calls_from_content(chunk_content)
        if calls:
            sections.append("=== CALLED FUNCTION DEFINITIONS ===")
            for call_name in calls[:8]:
                definition = self._find_definition(call_name)
                if definition:
                    code = self._get_symbol_code(definition)
                    if code:
                        sections.append(f"# {definition.qualified_name} ({definition.file_path}:{definition.start_line})")
                        sections.append(code)
                        sections.append("")

        # 9. Imports for context
        if scan_file:
            imports = self.db.query(ImportRelation).filter(
                ImportRelation.scan_id == self.scan_id,
                ImportRelation.importer_file == scan_file.file_path
            ).all()

            if imports:
                sections.append("=== IMPORTS ===")
                for imp in imports[:10]:
                    if imp.resolved_file:
                        sections.append(f"# {imp.imported_module} -> {imp.resolved_file}")
                    else:
                        sections.append(f"# {imp.imported_module} (external)")

        context = '\n'.join(sections)

        # Trim to token budget (rough estimate: 4 chars per token)
        max_chars = max_tokens * 4
        if len(context) > max_chars:
            context = context[:max_chars] + "\n... (context truncated)"

        return context

    def _detect_application_type(self) -> Dict:
        """Detect what type of application this is based on files and imports"""
        if self._app_type_cache:
            return self._app_type_cache

        files = self.db.query(ScanFile).filter(
            ScanFile.scan_id == self.scan_id
        ).all()

        file_paths = [f.file_path.lower() for f in files]
        all_paths = ' '.join(file_paths)

        # Check for web frameworks
        web_indicators = ['flask', 'django', 'fastapi', 'express', 'router', 'endpoint', 'handler', 'controller']
        cli_indicators = ['main.c', 'main.cpp', 'argparse', 'cli', 'argv', 'getopt']
        lib_indicators = ['lib/', 'include/', 'setup.py', 'package.json', '.h']

        evidence = []
        app_type = "Unknown"
        threat_model = "Unknown threat model"

        # Check imports for web frameworks
        imports = self.db.query(ImportRelation).filter(
            ImportRelation.scan_id == self.scan_id
        ).all()
        import_names = [i.imported_module.lower() for i in imports]

        if any(w in all_paths or w in ' '.join(import_names) for w in ['flask', 'django', 'fastapi']):
            app_type = "Web Application"
            evidence.append("Web framework detected")
            threat_model = "Remote attackers can send malicious input via HTTP requests. Input validation is critical."
        elif any(w in all_paths or w in ' '.join(import_names) for w in ['socket', 'network', 'server']):
            app_type = "Network Service"
            evidence.append("Network/socket code detected")
            threat_model = "Remote attackers can send malicious data over the network. All network input is untrusted."
        elif any(c in all_paths for c in cli_indicators):
            app_type = "CLI Tool"
            evidence.append("Command-line patterns detected")
            threat_model = "User already has local access. Vulnerabilities mainly matter if processing untrusted files."
        elif any(l in all_paths for l in lib_indicators):
            app_type = "Library"
            evidence.append("Library structure detected")
            threat_model = "Depends on how library is used. If exposed to untrusted input, vulnerabilities are exploitable."
        else:
            # Check for main function
            for f in files:
                try:
                    with open(f.file_path, 'r', encoding='utf-8', errors='ignore') as fp:
                        content = fp.read()
                        if 'int main(' in content or 'def main(' in content:
                            if 'argc' in content or 'argv' in content:
                                app_type = "CLI Tool"
                                evidence.append(f"main() with argv in {os.path.basename(f.file_path)}")
                                threat_model = "User has local access. Check if it processes untrusted input files."
                            else:
                                app_type = "Standalone Application"
                                evidence.append(f"main() in {os.path.basename(f.file_path)}")
                                threat_model = "Check how the application receives input."
                            break
                except:
                    pass

        if not evidence:
            evidence.append("No clear indicators found")

        self._app_type_cache = {
            'type': app_type,
            'evidence': ', '.join(evidence),
            'threat_model': threat_model
        }
        return self._app_type_cache

    def _find_entry_points(self) -> List[Dict]:
        """Find entry points where external input enters the application"""
        if self._entry_points_cache:
            return self._entry_points_cache

        entry_points = []

        files = self.db.query(ScanFile).filter(
            ScanFile.scan_id == self.scan_id
        ).all()

        entry_patterns = {
            # Web
            r'@app\.route|@router\.|def\s+\w+\(request': ('HTTP endpoint', 'high'),
            r'@api_view|@action': ('REST API endpoint', 'high'),
            # Network
            r'socket\.accept|recv\(|recvfrom\(': ('Network input', 'high'),
            # CLI
            r'int\s+main\s*\(|def\s+main\s*\(': ('Main entry', 'medium'),
            r'argv|sys\.argv|argparse': ('Command line args', 'medium'),
            # File
            r'open\s*\(|fopen\s*\(|ifstream': ('File input', 'medium'),
            r'getenv|os\.environ': ('Environment variable', 'medium'),
        }

        for f in files:
            try:
                with open(f.file_path, 'r', encoding='utf-8', errors='ignore') as fp:
                    lines = fp.readlines()
                    for i, line in enumerate(lines):
                        for pattern, (entry_type, risk) in entry_patterns.items():
                            if re.search(pattern, line):
                                entry_points.append({
                                    'name': line.strip()[:60],
                                    'file': os.path.basename(f.file_path),
                                    'line': i + 1,
                                    'type': entry_type,
                                    'risk': risk
                                })
            except:
                pass

        self._entry_points_cache = entry_points
        return entry_points

    def _get_file_context(self, scan_file: ScanFile, chunk: ScanFileChunk, context_lines: int = 20) -> str:
        """Get surrounding code in the same file for better context"""
        try:
            with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            start = max(0, chunk.start_line - context_lines - 1)
            end = min(len(lines), chunk.end_line + context_lines)

            result = []
            for i in range(start, end):
                prefix = ">>> " if chunk.start_line - 1 <= i < chunk.end_line else "    "
                result.append(f"{prefix}{i+1}: {lines[i].rstrip()}")

            return '\n'.join(result)
        except:
            return ""

    def _trace_call_chain_to_entry(self, func_names: List[str]) -> List[Dict]:
        """Trace call chain from entry points to vulnerable functions"""
        chains = []

        entry_points = self._find_entry_points()
        entry_funcs = set()

        # Extract function names from entry points
        for ep in entry_points:
            match = re.search(r'def\s+(\w+)|(\w+)\s*\(', ep['name'])
            if match:
                entry_funcs.add(match.group(1) or match.group(2))

        for func_name in func_names:
            # Simple BFS to find path from any entry point
            visited = set()
            queue = [(func_name, [func_name])]

            while queue and len(chains) < 5:
                current, path = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)

                # Check if we reached an entry point
                if current in entry_funcs:
                    chains.append({
                        'path': list(reversed(path)),
                        'entry_type': 'Entry point'
                    })
                    continue

                # Find callers
                callers = self._find_callers(current)
                for caller in callers[:3]:
                    if caller.name not in visited:
                        queue.append((caller.name, path + [caller.name]))

        return chains

    def _analyze_data_sources(self, content: str) -> List[Dict]:
        """Analyze where function parameters come from"""
        sources = []

        # Find function parameters
        func_pattern = r'(?:def|void|int|char\*?|string)\s+(\w+)\s*\(([^)]*)\)'
        matches = re.findall(func_pattern, content)

        dangerous_patterns = {
            'filename': ('User-controlled path', 'HIGH - path traversal risk'),
            'input': ('External input', 'HIGH - injection risk'),
            'user': ('User data', 'HIGH - untrusted'),
            'query': ('Query string', 'HIGH - injection risk'),
            'cmd': ('Command string', 'HIGH - command injection risk'),
            'buffer': ('Buffer', 'MEDIUM - overflow risk'),
            'data': ('Generic data', 'MEDIUM - check source'),
        }

        for func_name, params in matches:
            param_list = [p.strip().split()[-1].strip('*& ') for p in params.split(',') if p.strip()]
            for param in param_list:
                param_lower = param.lower()
                for pattern, (source, risk) in dangerous_patterns.items():
                    if pattern in param_lower:
                        sources.append({
                            'param': f"{func_name}({param})",
                            'source': source,
                            'risk': risk
                        })
                        break

        return sources

    def _get_chunk_content(self, chunk: ScanFileChunk) -> str:
        """Get the actual content of a chunk"""
        scan_file = self.db.query(ScanFile).filter(
            ScanFile.id == chunk.scan_file_id
        ).first()

        if not scan_file:
            return ""

        try:
            with open(scan_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            return ''.join(lines[chunk.start_line - 1:chunk.end_line])
        except Exception:
            return ""

    def _extract_calls_from_content(self, content: str) -> List[str]:
        """Extract function call names from content"""
        # Simple regex for function calls
        # Python: func(, obj.method(
        # C: func(
        pattern = r'(?:^|[^\w])([a-zA-Z_][\w\.]*)\s*\('
        matches = re.findall(pattern, content)

        # Filter out keywords
        keywords = {'if', 'for', 'while', 'switch', 'return', 'print', 'def', 'class'}
        return [m for m in matches if m not in keywords and not m.startswith('__')]

    def _extract_function_names(self, content: str) -> List[str]:
        """Extract function definition names from content"""
        # Python: def func_name(
        # C: type func_name(
        py_pattern = r'def\s+(\w+)\s*\('
        c_pattern = r'(?:void|int|char|bool|float|double|[\w\*]+)\s+(\w+)\s*\('

        py_funcs = re.findall(py_pattern, content)
        c_funcs = re.findall(c_pattern, content)

        return py_funcs + c_funcs

    def _find_definition(self, symbol_name: str) -> Optional[Symbol]:
        """Find where a symbol is defined"""
        # Strip object prefix for method calls (obj.method -> method)
        if '.' in symbol_name:
            symbol_name = symbol_name.split('.')[-1]

        # Try exact name match
        symbol = self.db.query(Symbol).filter(
            Symbol.scan_id == self.scan_id,
            Symbol.name == symbol_name
        ).first()

        return symbol

    def _find_callers(self, func_name: str) -> List[Symbol]:
        """Find all functions that call this function"""
        # Find the function symbol
        func = self.db.query(Symbol).filter(
            Symbol.scan_id == self.scan_id,
            Symbol.name == func_name,
            Symbol.symbol_type.in_(['function', 'method'])
        ).first()

        if not func:
            return []

        # Find references to it
        refs = self.db.query(SymbolReference).filter(
            SymbolReference.scan_id == self.scan_id,
            SymbolReference.symbol_id == func.id,
            SymbolReference.reference_type == 'call'
        ).all()

        # Get the calling functions
        callers = []
        for ref in refs:
            if ref.from_symbol_id:
                caller = self.db.query(Symbol).filter(
                    Symbol.id == ref.from_symbol_id
                ).first()
                if caller:
                    callers.append(caller)

        return callers

    def _find_callees(self, func_name: str) -> List[Symbol]:
        """Find all functions that this function calls"""
        func = self.db.query(Symbol).filter(
            Symbol.scan_id == self.scan_id,
            Symbol.name == func_name,
            Symbol.symbol_type.in_(['function', 'method'])
        ).first()

        if not func:
            return []

        # Find calls from this function
        refs = self.db.query(SymbolReference).filter(
            SymbolReference.scan_id == self.scan_id,
            SymbolReference.from_symbol_id == func.id,
            SymbolReference.reference_type == 'call'
        ).all()

        callees = []
        for ref in refs:
            if ref.symbol_id:
                callee = self.db.query(Symbol).filter(
                    Symbol.id == ref.symbol_id
                ).first()
                if callee:
                    callees.append(callee)

        return callees

    def _get_symbol_code(self, symbol: Symbol) -> str:
        """Get the source code for a symbol"""
        try:
            with open(symbol.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            return ''.join(lines[symbol.start_line - 1:symbol.end_line])
        except Exception:
            return ""

    def get_data_flow(self, chunk: ScanFileChunk, var_name: str) -> str:
        """
        Trace data flow for a variable.
        Returns description of where data comes from.
        """
        # Simplified data flow analysis
        content = self._get_chunk_content(chunk)

        # Find assignments to this variable
        assignment_pattern = rf'{var_name}\s*=\s*(.+)'
        matches = re.findall(assignment_pattern, content)

        if matches:
            return f"Variable '{var_name}' assigned from: {', '.join(matches[:3])}"

        return f"Variable '{var_name}' source unknown"

    async def get_context_for_file(self, file_path: str, line_number: int,
                                    context_lines: int = 50, max_tokens: int = 8000) -> str:
        """
        Get context for a finding by file path and line number.
        Used for Joern findings that don't have chunks.

        Returns focused context: surrounding code, function containing the line,
        and relevant callers/callees.
        """
        sections = []

        # Resolve file path - try multiple locations
        resolved_path = self._resolve_file_path(file_path)
        if not resolved_path:
            return f"Could not locate file: {file_path}"

        try:
            with open(resolved_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            return f"Error reading file {file_path}: {e}"

        total_lines = len(lines)

        # 1. Show the vulnerable function (find function boundaries)
        func_start, func_end, func_name = self._find_containing_function(lines, line_number)

        if func_name:
            sections.append(f"=== FUNCTION: {func_name} ===")
            sections.append(f"File: {os.path.basename(resolved_path)}")
            sections.append("")

            # Show the function with line numbers, highlighting the vulnerable line
            for i in range(func_start, min(func_end + 1, total_lines)):
                prefix = ">>> " if i + 1 == line_number else "    "
                sections.append(f"{prefix}{i + 1}: {lines[i].rstrip()}")
        else:
            # No function found, show context around the line
            sections.append(f"=== CODE CONTEXT ===")
            sections.append(f"File: {os.path.basename(resolved_path)}")
            sections.append("")

            start = max(0, line_number - context_lines - 1)
            end = min(total_lines, line_number + context_lines)

            for i in range(start, end):
                prefix = ">>> " if i + 1 == line_number else "    "
                sections.append(f"{prefix}{i + 1}: {lines[i].rstrip()}")

        sections.append("")

        # 2. Find callers of this function (if we found one)
        if func_name:
            callers = self._find_callers(func_name)
            if callers:
                sections.append("=== CALLERS (who calls this function) ===")
                for caller in callers[:3]:
                    code = self._get_symbol_code(caller)
                    if code:
                        sections.append(f"# {caller.name} in {os.path.basename(caller.file_path)}:{caller.start_line}")
                        # Show just the relevant part (truncate long functions)
                        code_lines = code.split('\n')
                        if len(code_lines) > 20:
                            sections.append('\n'.join(code_lines[:20]))
                            sections.append(f"    ... ({len(code_lines) - 20} more lines)")
                        else:
                            sections.append(code)
                        sections.append("")

        # 3. Data source hints from parameter names
        if func_name and func_start < total_lines:
            func_content = ''.join(lines[func_start:min(func_end + 1, total_lines)])
            data_sources = self._analyze_data_sources(func_content)
            if data_sources:
                sections.append("=== POTENTIAL DATA SOURCES ===")
                for ds in data_sources[:5]:
                    sections.append(f"- {ds['param']}: {ds['source']} ({ds['risk']})")
                sections.append("")

        context = '\n'.join(sections)

        # Trim to token budget
        max_chars = max_tokens * 4
        if len(context) > max_chars:
            context = context[:max_chars] + "\n... (context truncated)"

        return context

    def _resolve_file_path(self, file_path: str) -> Optional[str]:
        """Resolve a file path to an actual file on disk, trying multiple locations"""
        # Try as-is first
        if os.path.exists(file_path):
            return file_path

        # Try relative to sandbox
        sandbox_paths = [
            f"sandbox/{self.scan_id}/{file_path}",
            f"sandbox/{self.scan_id}/{os.path.basename(file_path)}",
        ]

        # Also check if file_path starts with /app/ (from Joern Docker)
        if file_path.startswith('/app/'):
            clean_path = file_path[5:]  # Remove /app/
            sandbox_paths.extend([
                f"sandbox/{self.scan_id}/{clean_path}",
                clean_path,
            ])

        # Check scan files in database for matching basename
        basename = os.path.basename(file_path)
        scan_files = self.db.query(ScanFile).filter(
            ScanFile.scan_id == self.scan_id
        ).all()

        for sf in scan_files:
            if os.path.basename(sf.file_path) == basename:
                if os.path.exists(sf.file_path):
                    return sf.file_path

        # Try sandbox paths
        for sp in sandbox_paths:
            if os.path.exists(sp):
                return sp

        return None

    def _find_containing_function(self, lines: List[str], target_line: int) -> tuple:
        """
        Find the function that contains the target line.
        Returns (start_line_idx, end_line_idx, function_name) or (0, 0, None) if not found.
        """
        # Patterns for function definitions
        func_patterns = [
            # C/C++ function
            r'^(?:static\s+)?(?:inline\s+)?(?:[\w\*]+\s+)+(\w+)\s*\([^)]*\)\s*\{?\s*$',
            # Python function
            r'^def\s+(\w+)\s*\([^)]*\)\s*:',
            # UEFI/EDK2 style
            r'^(?:VOID|EFI_STATUS|BOOLEAN|UINTN|UINT\d+)\s*\n?(\w+)\s*\(',
        ]

        # Find function start (search backwards from target line)
        func_start = 0
        func_name = None
        brace_depth = 0

        for i in range(target_line - 1, -1, -1):
            line = lines[i] if i < len(lines) else ""

            for pattern in func_patterns:
                match = re.search(pattern, line, re.MULTILINE)
                if match:
                    func_name = match.group(1)
                    func_start = i
                    break

            if func_name:
                break

        if not func_name:
            return (0, 0, None)

        # Find function end (search for matching closing brace or next function)
        func_end = func_start
        brace_depth = 0
        started_body = False

        for i in range(func_start, len(lines)):
            line = lines[i]

            # Count braces
            brace_depth += line.count('{') - line.count('}')

            if '{' in line:
                started_body = True

            # For Python, look for dedent
            if line.startswith('def ') and i > func_start:
                func_end = i - 1
                break

            # For C, check brace balance
            if started_body and brace_depth <= 0:
                func_end = i
                break

            func_end = i

        # Limit function size to avoid huge context
        max_func_lines = 150
        if func_end - func_start > max_func_lines:
            # Center around the target line
            half = max_func_lines // 2
            new_start = max(func_start, target_line - 1 - half)
            new_end = min(func_end, target_line - 1 + half)
            return (new_start, new_end, func_name)

        return (func_start, func_end, func_name)
