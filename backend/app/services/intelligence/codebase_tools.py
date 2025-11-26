"""
Codebase navigation tools for agentic verification and interactive chat.
Provides a clean interface for LLM agents to explore code.
"""
import os
import re
import subprocess
import glob as glob_module
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from sqlalchemy.orm import Session

from app.models.scanner_models import Symbol, SymbolReference, ScanFile
from app.services.intelligence.ast_parser import ASTParser


@dataclass
class ToolResult:
    """Result from a tool call"""
    success: bool
    data: Any
    error: Optional[str] = None

    def to_string(self) -> str:
        """Format result for LLM consumption"""
        if not self.success:
            return f"Error: {self.error}"
        if isinstance(self.data, str):
            return self.data
        if isinstance(self.data, list):
            return "\n".join(str(item) for item in self.data)
        return str(self.data)


class CodebaseTools:
    """
    Tools for LLM agents to navigate and explore a codebase.
    Designed for use in agentic verification and interactive chat.
    """

    # Tool definitions for the LLM
    TOOL_DEFINITIONS = [
        {
            "name": "list_files",
            "description": "List all files in the codebase, optionally filtered by pattern. Use this FIRST to discover what files exist.",
            "parameters": {
                "pattern": "(optional) Glob pattern to filter files (e.g., '*.cpp', '**/*.py')",
                "directory": "(optional) Subdirectory to list (relative to root)"
            }
        },
        {
            "name": "read_file",
            "description": "Read the contents of a file, optionally specifying line range. If file not found, returns available files.",
            "parameters": {
                "path": "File path (relative to scan root or absolute)",
                "start_line": "(optional) Starting line number (1-indexed)",
                "end_line": "(optional) Ending line number (inclusive)"
            }
        },
        {
            "name": "find_definition",
            "description": "Find where a function, class, or variable is defined",
            "parameters": {
                "symbol": "Name of the symbol to find (e.g., 'execute_hook', 'UserClass')"
            }
        },
        {
            "name": "find_callers",
            "description": "Find all places that call a function",
            "parameters": {
                "function": "Name of the function to find callers for"
            }
        },
        {
            "name": "find_references",
            "description": "Find all uses of a symbol (variables, functions, classes)",
            "parameters": {
                "symbol": "Name of the symbol to find references for"
            }
        },
        {
            "name": "search_code",
            "description": "Search for a pattern across the codebase (grep-like)",
            "parameters": {
                "pattern": "Regex pattern to search for",
                "file_pattern": "(optional) Glob pattern to filter files (e.g., '*.c')"
            }
        },
        {
            "name": "get_function_body",
            "description": "Get the complete source code of a function",
            "parameters": {
                "function": "Name of the function"
            }
        },
        {
            "name": "list_functions",
            "description": "List all functions in a file",
            "parameters": {
                "path": "File path"
            }
        },
        {
            "name": "trace_data_flow",
            "description": "Trace where a variable's value comes from (backward) or goes to (forward)",
            "parameters": {
                "variable": "Name of the variable to trace",
                "file": "File where the variable is used",
                "line": "Line number where the variable appears",
                "direction": "'backward' to find source, 'forward' to find sinks"
            }
        },
        {
            "name": "get_call_graph",
            "description": "Get functions called by a function and functions that call it",
            "parameters": {
                "function": "Name of the function"
            }
        },
        {
            "name": "find_entry_points",
            "description": "Find entry points where external input enters (network, file, CLI)",
            "parameters": {}
        }
    ]

    def __init__(self, scan_id: int, root_dir: str, db: Session):
        """
        Initialize codebase tools.

        Args:
            scan_id: The scan ID for symbol lookups
            root_dir: Root directory of the scanned codebase
            db: Database session for symbol queries
        """
        self.scan_id = scan_id
        self.root_dir = root_dir
        self.db = db
        self.parser = ASTParser()
        self._file_cache: Dict[str, List[str]] = {}

    def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> ToolResult:
        """
        Execute a tool by name with given parameters.

        Args:
            tool_name: Name of the tool to execute
            params: Dictionary of parameters

        Returns:
            ToolResult with success/failure and data
        """
        tool_map = {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "find_definition": self.find_definition,
            "find_callers": self.find_callers,
            "find_references": self.find_references,
            "search_code": self.search_code,
            "get_function_body": self.get_function_body,
            "list_functions": self.list_functions,
            "trace_data_flow": self.trace_data_flow,
            "get_call_graph": self.get_call_graph,
            "find_entry_points": self.find_entry_points,
        }

        if tool_name not in tool_map:
            return ToolResult(success=False, data=None, error=f"Unknown tool: {tool_name}")

        try:
            return tool_map[tool_name](**params)
        except Exception as e:
            return ToolResult(success=False, data=None, error=str(e))

    def _resolve_path(self, path: str) -> str:
        """Resolve a path relative to root_dir"""
        if os.path.isabs(path):
            return path
        return os.path.join(self.root_dir, path)

    def _get_all_files(self, pattern: str = None, directory: str = None) -> List[str]:
        """
        Get all files in the codebase, optionally filtered by pattern.
        Returns relative paths.
        """
        base_dir = self.root_dir
        if directory:
            base_dir = os.path.join(self.root_dir, directory)

        if not os.path.exists(base_dir):
            return []

        files = []
        if pattern:
            # Use glob for pattern matching
            if '**' in pattern:
                matches = glob_module.glob(os.path.join(base_dir, pattern), recursive=True)
            else:
                matches = glob_module.glob(os.path.join(base_dir, '**', pattern), recursive=True)
            files = [f for f in matches if os.path.isfile(f)]
        else:
            # Walk the directory tree
            for root, dirs, filenames in os.walk(base_dir):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for filename in filenames:
                    if not filename.startswith('.'):
                        files.append(os.path.join(root, filename))

        # Convert to relative paths
        rel_files = []
        for f in files:
            try:
                rel_files.append(os.path.relpath(f, self.root_dir))
            except ValueError:
                rel_files.append(f)

        return sorted(rel_files)

    def _fuzzy_find_file(self, filename: str) -> Optional[str]:
        """
        Try to find a file even if the exact path is wrong.
        Returns the first matching file path or None.
        """
        # Get the basename
        basename = os.path.basename(filename)

        # Search for files with this name
        all_files = self._get_all_files()

        # Exact basename match
        for f in all_files:
            if os.path.basename(f) == basename:
                return f

        # Case-insensitive match
        for f in all_files:
            if os.path.basename(f).lower() == basename.lower():
                return f

        # Partial match (filename contains the search term)
        for f in all_files:
            if basename.lower() in os.path.basename(f).lower():
                return f

        return None

    def _get_file_lines(self, path: str) -> List[str]:
        """Get file lines with caching"""
        if path not in self._file_cache:
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    self._file_cache[path] = f.readlines()
            except Exception:
                self._file_cache[path] = []
        return self._file_cache[path]

    def list_files(self, pattern: str = None, directory: str = None) -> ToolResult:
        """List all files in the codebase, optionally filtered by pattern."""
        try:
            files = self._get_all_files(pattern=pattern, directory=directory)

            if not files:
                if pattern:
                    return ToolResult(
                        success=True,
                        data=f"No files matching '{pattern}' found in codebase."
                    )
                return ToolResult(success=True, data="No files found in codebase.")

            # Group by directory for better readability
            result_lines = [f"Found {len(files)} files in codebase:"]

            # Show directory structure
            current_dir = None
            for f in files:
                file_dir = os.path.dirname(f) or "."
                if file_dir != current_dir:
                    current_dir = file_dir
                    result_lines.append(f"\n{current_dir}/")
                result_lines.append(f"  {os.path.basename(f)}")

            return ToolResult(success=True, data="\n".join(result_lines))

        except Exception as e:
            return ToolResult(success=False, data=None, error=str(e))

    def read_file(self, path: str, start_line: int = None, end_line: int = None) -> ToolResult:
        """Read file contents, optionally a specific line range"""
        full_path = self._resolve_path(path)

        if not os.path.exists(full_path):
            # Try fuzzy matching to find the file
            fuzzy_match = self._fuzzy_find_file(path)
            if fuzzy_match:
                # Found a match - try reading that instead
                return self.read_file(fuzzy_match, start_line, end_line)

            # No match found - provide helpful error with available files
            all_files = self._get_all_files()
            basename = os.path.basename(path)

            # Find similar files
            similar = [f for f in all_files if basename.lower() in f.lower() or
                       any(part.lower() in f.lower() for part in basename.split('_'))][:5]

            error_msg = f"File not found: {path}"
            if similar:
                error_msg += f"\n\nDid you mean one of these?\n  " + "\n  ".join(similar)
            else:
                # Show available files with same extension
                ext = os.path.splitext(path)[1]
                if ext:
                    same_ext = [f for f in all_files if f.endswith(ext)][:10]
                    if same_ext:
                        error_msg += f"\n\nAvailable {ext} files:\n  " + "\n  ".join(same_ext)
                    else:
                        error_msg += f"\n\nNo {ext} files found. Available files:\n  " + "\n  ".join(all_files[:10])
                else:
                    error_msg += f"\n\nAvailable files:\n  " + "\n  ".join(all_files[:10])

            if len(all_files) > 10:
                error_msg += f"\n  ... and {len(all_files) - 10} more"

            return ToolResult(success=False, data=None, error=error_msg)

        lines = self._get_file_lines(full_path)

        if start_line is not None:
            start_idx = max(0, start_line - 1)
            end_idx = end_line if end_line else len(lines)
            selected = lines[start_idx:end_idx]

            # Format with line numbers
            result = []
            for i, line in enumerate(selected, start=start_line):
                result.append(f"{i:4d} | {line.rstrip()}")
            return ToolResult(success=True, data="\n".join(result))
        else:
            # Return whole file with line numbers
            result = []
            for i, line in enumerate(lines, start=1):
                result.append(f"{i:4d} | {line.rstrip()}")
            return ToolResult(success=True, data="\n".join(result))

    def find_definition(self, symbol: str) -> ToolResult:
        """Find where a symbol is defined"""
        # First check the database
        db_symbol = self.db.query(Symbol).filter(
            Symbol.scan_id == self.scan_id,
            Symbol.name == symbol
        ).first()

        if db_symbol:
            # Get the code
            lines = self._get_file_lines(db_symbol.file_path)
            code = "".join(lines[db_symbol.start_line - 1:db_symbol.end_line])

            rel_path = os.path.relpath(db_symbol.file_path, self.root_dir)
            return ToolResult(
                success=True,
                data=f"Found {db_symbol.symbol_type} '{symbol}' at {rel_path}:{db_symbol.start_line}-{db_symbol.end_line}\n\n{code}"
            )

        # Fallback: grep for definition patterns
        patterns = [
            rf"def\s+{re.escape(symbol)}\s*\(",  # Python function
            rf"class\s+{re.escape(symbol)}\s*[:\(]",  # Python class
            rf"(?:void|int|char|bool|float|double|[\w\*]+)\s+{re.escape(symbol)}\s*\(",  # C function
            rf"#define\s+{re.escape(symbol)}\b",  # C macro
            rf"struct\s+{re.escape(symbol)}\s*\{{",  # C struct
        ]

        for pattern in patterns:
            result = self.search_code(pattern=pattern)
            if result.success and result.data:
                return ToolResult(
                    success=True,
                    data=f"Definition found:\n{result.data}"
                )

        return ToolResult(success=False, data=None, error=f"No definition found for '{symbol}'")

    def find_callers(self, function: str) -> ToolResult:
        """Find all places that call a function"""
        # Search for function call pattern
        pattern = rf"\b{re.escape(function)}\s*\("

        result = self.search_code(pattern=pattern)
        if not result.success:
            return result

        if not result.data:
            return ToolResult(success=True, data=f"No callers found for '{function}'")

        return ToolResult(
            success=True,
            data=f"Callers of '{function}':\n{result.data}"
        )

    def find_references(self, symbol: str) -> ToolResult:
        """Find all uses of a symbol"""
        pattern = rf"\b{re.escape(symbol)}\b"
        return self.search_code(pattern=pattern)

    def search_code(self, pattern: str, file_pattern: str = None) -> ToolResult:
        """Search for a pattern across the codebase"""
        try:
            cmd = ["grep", "-rn", "-E", pattern, self.root_dir]

            if file_pattern:
                cmd = ["grep", "-rn", "-E", f"--include={file_pattern}", pattern, self.root_dir]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Format results with relative paths
                lines = []
                for line in result.stdout.strip().split("\n")[:50]:  # Limit to 50 results
                    if line:
                        # Convert absolute to relative path
                        if self.root_dir in line:
                            line = line.replace(self.root_dir + "/", "")
                        lines.append(line)
                return ToolResult(success=True, data="\n".join(lines))
            elif result.returncode == 1:
                # No matches - provide helpful context
                all_files = self._get_all_files(pattern=file_pattern)
                if file_pattern:
                    msg = f"No matches for '{pattern}' in {file_pattern} files."
                else:
                    msg = f"No matches for '{pattern}' in codebase."

                if all_files:
                    msg += f"\n\nSearched {len(all_files)} files. Available files:\n  " + "\n  ".join(all_files[:15])
                    if len(all_files) > 15:
                        msg += f"\n  ... and {len(all_files) - 15} more"
                else:
                    msg += "\n\nNo source files found in codebase."

                # Suggest using list_files if the pattern might be a filename
                if '.' in pattern and '\\' not in pattern:
                    msg += f"\n\nTip: If '{pattern}' is a filename, use list_files to find it."

                return ToolResult(success=True, data=msg)
            else:
                return ToolResult(success=False, data=None, error=result.stderr)

        except subprocess.TimeoutExpired:
            return ToolResult(success=False, data=None, error="Search timed out")
        except Exception as e:
            return ToolResult(success=False, data=None, error=str(e))

    def get_function_body(self, function: str) -> ToolResult:
        """Get the complete source code of a function"""
        # Use find_definition which already returns the code
        result = self.find_definition(function)
        if result.success:
            return result

        # Fallback: try to find and parse the function
        search_result = self.search_code(pattern=rf"(?:def|void|int|char|bool)\s+{re.escape(function)}\s*\(")
        if not search_result.success or not search_result.data:
            return ToolResult(success=False, data=None, error=f"Function '{function}' not found")

        # Parse first match
        first_match = search_result.data.split("\n")[0]
        if ":" in first_match:
            parts = first_match.split(":")
            if len(parts) >= 2:
                file_path = parts[0]
                line_num = int(parts[1])

                # Read context around the function (up to 100 lines)
                return self.read_file(file_path, line_num, line_num + 100)

        return search_result

    def list_functions(self, path: str) -> ToolResult:
        """List all functions in a file"""
        full_path = self._resolve_path(path)

        if not os.path.exists(full_path):
            return ToolResult(success=False, data=None, error=f"File not found: {path}")

        try:
            parsed = self.parser.parse_file(full_path)
            functions = parsed.extract_functions()

            if not functions:
                return ToolResult(success=True, data="No functions found in file")

            result = []
            for func in functions:
                params_str = ", ".join(func.params[:3])
                if len(func.params) > 3:
                    params_str += ", ..."
                result.append(f"  {func.name}({params_str}) at lines {func.start_line}-{func.end_line}")

            return ToolResult(success=True, data=f"Functions in {path}:\n" + "\n".join(result))

        except Exception as e:
            return ToolResult(success=False, data=None, error=str(e))

    def trace_data_flow(self, variable: str, file: str, line: int, direction: str = "backward") -> ToolResult:
        """Trace data flow for a variable"""
        full_path = self._resolve_path(file)
        lines = self._get_file_lines(full_path)

        if not lines:
            return ToolResult(success=False, data=None, error=f"Could not read file: {file}")

        results = []

        if direction == "backward":
            # Search backwards for assignments to this variable
            for i in range(line - 1, max(0, line - 50), -1):
                current_line = lines[i]
                # Look for assignments: var = ..., var := ..., type var = ...
                assignment_patterns = [
                    rf"\b{re.escape(variable)}\s*=\s*(.+)",
                    rf"\b{re.escape(variable)}\s*:=\s*(.+)",
                    rf"(?:int|char|void|bool|string|auto)\s*\*?\s*{re.escape(variable)}\s*=\s*(.+)",
                ]
                for pattern in assignment_patterns:
                    match = re.search(pattern, current_line)
                    if match:
                        results.append(f"Line {i+1}: {current_line.strip()}")
                        # Try to trace the source value recursively
                        source = match.group(1).strip().rstrip(';')
                        if source and not source.startswith('"') and not source.isdigit():
                            # It's assigned from another variable/function
                            results.append(f"  -> Value comes from: {source}")

            # Also check function parameters
            for i in range(max(0, line - 100), line):
                current_line = lines[i]
                if re.search(rf"(?:def|void|int|char)\s+\w+\s*\([^)]*\b{re.escape(variable)}\b", current_line):
                    results.append(f"Line {i+1}: '{variable}' is a function parameter: {current_line.strip()}")
                    break

        else:  # forward
            # Search forward for uses of this variable
            for i in range(line, min(len(lines), line + 50)):
                current_line = lines[i]
                if re.search(rf"\b{re.escape(variable)}\b", current_line):
                    results.append(f"Line {i+1}: {current_line.strip()}")

        if not results:
            return ToolResult(success=True, data=f"No data flow found for '{variable}' ({direction})")

        return ToolResult(success=True, data="\n".join(results))

    def get_call_graph(self, function: str) -> ToolResult:
        """Get functions called by and calling a function"""
        results = []

        # Find callers (what calls this function)
        callers_result = self.find_callers(function)
        if callers_result.success and callers_result.data:
            results.append(f"=== Functions that call '{function}' ===")
            results.append(callers_result.data[:2000])  # Limit size

        # Find callees (what this function calls)
        # First get the function body
        body_result = self.get_function_body(function)
        if body_result.success and body_result.data:
            results.append(f"\n=== Functions called by '{function}' ===")

            # Extract function calls from the body
            call_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            calls = set(re.findall(call_pattern, body_result.data))

            # Filter out common keywords
            keywords = {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'printf', 'fprintf'}
            calls = calls - keywords - {function}  # Remove self-calls

            if calls:
                results.append("Calls: " + ", ".join(sorted(calls)[:20]))
            else:
                results.append("No function calls found")

        if not results:
            return ToolResult(success=False, data=None, error=f"Could not analyze call graph for '{function}'")

        return ToolResult(success=True, data="\n".join(results))

    def find_entry_points(self) -> ToolResult:
        """Find entry points where external input enters"""
        entry_patterns = {
            # Network
            r"recv\s*\(": "Network input (recv)",
            r"recvfrom\s*\(": "Network input (recvfrom)",
            r"socket\s*\(": "Socket creation",
            r"accept\s*\(": "Socket accept",
            # File
            r"fopen\s*\(": "File open",
            r"open\s*\(": "File open",
            r"fread\s*\(": "File read",
            r"fgets\s*\(": "File/stdin read",
            # CLI
            r"int\s+main\s*\([^)]*argc": "CLI entry (main with args)",
            r"getopt\s*\(": "CLI option parsing",
            r"argv\[": "CLI argument access",
            # Environment
            r"getenv\s*\(": "Environment variable",
            # Web (Python)
            r"@app\.route": "Flask HTTP endpoint",
            r"@router\.": "FastAPI endpoint",
            r"request\.": "HTTP request access",
        }

        results = []

        for pattern, desc in entry_patterns.items():
            search_result = self.search_code(pattern=pattern)
            if search_result.success and search_result.data and search_result.data != "No matches found":
                matches = search_result.data.split("\n")[:5]  # Limit per pattern
                results.append(f"\n{desc}:")
                for match in matches:
                    results.append(f"  {match}")

        if not results:
            return ToolResult(success=True, data="No obvious entry points found")

        return ToolResult(success=True, data="Entry points found:" + "\n".join(results))

    def get_tool_descriptions(self) -> str:
        """Get formatted tool descriptions for the LLM prompt"""
        lines = ["Available tools:"]
        for tool in self.TOOL_DEFINITIONS:
            lines.append(f"\n{tool['name']}: {tool['description']}")
            lines.append("  Parameters:")
            for param, desc in tool['parameters'].items():
                lines.append(f"    - {param}: {desc}")
        return "\n".join(lines)
