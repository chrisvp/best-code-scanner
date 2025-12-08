"""
Fix generation service with Quick Fix and Agent Fix modes.

Quick Fix: Single-shot LLM call with full file context
Agent Fix: Multi-turn agentic approach with tool use, saves diffs to files
"""
import os
import re
import json
import difflib
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session

from app.models.models import Finding, Scan
from app.services.llm_provider import llm_provider


class FixGenerator:
    """Generates security vulnerability fixes using LLM"""

    def __init__(self, db: Session, step_callback=None, finding_id: int = None, model_name: str = None):
        self.db = db
        self.scan_root = None  # Root directory of the scanned code
        self.step_callback = step_callback  # Optional callback for streaming progress
        self.finding_id = finding_id  # For naming diff files
        self.model_name = model_name  # For naming diff files
        self.diff_file_path = None  # Path to saved diff file (set after save_fix)

    QUICK_FIX_PROMPT = """You are a security expert fixing a vulnerability. Generate a unified diff showing the fix.

=== VULNERABILITY ===
{title}
Category: {category}
Severity: {severity}

=== FILE CONTEXT ===
File: {file_path}
Language: {language}

{file_context}

=== VULNERABLE CODE (around line {line_number}) ===
{snippet}

=== VULNERABILITY DETAILS ===
{vulnerability_details}

=== OUTPUT FORMAT ===
Generate a unified diff showing the fix. Your response must be:
- Standard unified diff format (like `diff -u` or `git diff` output)
- Start with --- a/{file_path} and +++ b/{file_path} headers
- Use @@ -line,count +line,count @@ hunk headers with correct line numbers
- Lines starting with - are removed, + are added, space are context
- Include 3 lines of context before and after changes
- NO explanations, commentary, or markdown - ONLY the raw diff
- Do NOT wrap in code blocks

Example format:
--- a/path/to/file.c
+++ b/path/to/file.c
@@ -40,7 +40,7 @@
 context line before
 context line before
 context line before
-vulnerable line to remove
+fixed line to add
 context line after
 context line after
 context line after

Output the unified diff now:"""

    AGENT_SYSTEM_PROMPT = """You are a security expert fixing a vulnerability. You MUST use tools to read files and save your fix as a DIFF.

TOOLS:
- read_file(path): Read file contents
- search_code(query): Search for patterns
- list_files(directory): List directory contents
- save_fix(file_path, diff): Save your fix as a unified diff - REQUIRED to complete

WORKFLOW:
1. Call read_file to understand the vulnerable code and surrounding context
2. Optionally use search_code to understand related code
3. Call save_fix with a UNIFIED DIFF showing your fix

UNIFIED DIFF FORMAT for save_fix:
The diff parameter must be a standard unified diff (like git diff output):
```
--- a/filename
+++ b/filename
@@ -LINE,COUNT +LINE,COUNT @@
 context line (unchanged)
 context line (unchanged)
-old vulnerable line (to remove)
+new fixed line (to add)
 context line (unchanged)
```

RULES:
- Lines starting with space are context (unchanged)
- Lines starting with - are removed
- Lines starting with + are added
- Include 3 lines of context before and after changes
- Use correct line numbers in the @@ header
- Only include the changed sections, not the entire file

EXAMPLE: To fix a buffer overflow on line 42:
```
--- a/file.c
+++ b/file.c
@@ -39,7 +39,7 @@
     char buffer[256];
     char *input = get_user_input();

-    strcpy(buffer, input);
+    strncpy(buffer, input, sizeof(buffer) - 1);
+    buffer[sizeof(buffer) - 1] = '\\0';

     process(buffer);
 }
```

Start by reading the vulnerable file to understand the context."""

    AGENT_TOOLS = [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read the contents of a file in the codebase",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the file to read"
                        }
                    },
                    "required": ["path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "search_code",
                "description": "Search for code patterns in the codebase",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query (function name, variable, pattern)"
                        }
                    },
                    "required": ["query"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_files",
                "description": "List files in a directory",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "directory": {
                            "type": "string",
                            "description": "Directory path to list"
                        }
                    },
                    "required": ["directory"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "save_fix",
                "description": "Save your security fix as a unified diff. The diff will be saved to a .diff file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file being fixed (same path you read)"
                        },
                        "diff": {
                            "type": "string",
                            "description": "Unified diff showing your fix (standard diff format with --- +++ @@ headers)"
                        }
                    },
                    "required": ["file_path", "diff"]
                }
            }
        }
    ]


    def _get_file_context(self, file_path: str, line_number: int, context_lines: int = 50) -> str:
        """Get file content with context around the vulnerable line"""
        try:
            if not os.path.exists(file_path):
                return "(File not found)"

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            total_lines = len(lines)
            start = max(0, line_number - context_lines - 1)
            end = min(total_lines, line_number + context_lines)

            result = []
            for i in range(start, end):
                line_num = i + 1
                marker = ">>>" if abs(line_num - line_number) <= 3 else "   "
                result.append(f"{marker} {line_num:4d} | {lines[i].rstrip()}")

            if start > 0:
                result.insert(0, f"... ({start} lines above)")
            if end < total_lines:
                result.append(f"... ({total_lines - end} lines below)")

            return "\n".join(result)
        except Exception as e:
            return f"(Error reading file: {e})"

    def _get_language(self, file_path: str) -> str:
        """Detect language from file extension"""
        ext = os.path.splitext(file_path)[1].lower()
        lang_map = {
            '.py': 'Python',
            '.c': 'C',
            '.cpp': 'C++',
            '.cc': 'C++',
            '.h': 'C/C++ Header',
            '.hpp': 'C++ Header',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.go': 'Go',
            '.rs': 'Rust',
            '.rb': 'Ruby',
            '.php': 'PHP',
        }
        return lang_map.get(ext, 'Unknown')

    def _find_scan_root(self, finding: Finding) -> Optional[str]:
        """Find the root directory of the scan"""
        # Try to get from scan
        if finding.scan_id:
            scan = self.db.query(Scan).filter(Scan.id == finding.scan_id).first()
            if scan and scan.target_url:
                # target_url might be a local path
                if os.path.isdir(scan.target_url):
                    return scan.target_url

        # Try from file path
        if finding.file_path and os.path.exists(finding.file_path):
            # Walk up to find project root (look for common markers)
            path = os.path.dirname(os.path.abspath(finding.file_path))
            for _ in range(10):  # Max 10 levels up
                if any(os.path.exists(os.path.join(path, marker))
                       for marker in ['.git', 'setup.py', 'package.json', 'Makefile', 'CMakeLists.txt']):
                    return path
                parent = os.path.dirname(path)
                if parent == path:
                    break
                path = parent

        return None

    async def quick_fix(
        self,
        finding: Finding,
        model: Optional[str] = None
    ) -> str:
        """
        Generate a fix using single-shot LLM with full file context.
        Fast but less accurate for complex fixes.
        """
        file_context = self._get_file_context(
            finding.file_path,
            finding.line_number or 1,
            context_lines=75  # More context for better fixes
        )

        prompt = self.QUICK_FIX_PROMPT.format(
            title=finding.description or "Security Vulnerability",
            category=finding.category or "Unknown",
            severity=finding.severity or "Medium",
            file_path=finding.file_path,
            language=self._get_language(finding.file_path),
            line_number=finding.line_number or 1,
            file_context=file_context,
            snippet=finding.snippet or "(No snippet)",
            vulnerability_details=finding.vulnerability_details or finding.description or ""
        )

        messages = [{"role": "user", "content": prompt}]

        result = await llm_provider.chat_completion(
            messages=messages,
            model=model,
            max_tokens=4096
        )

        content = result.get("content", "")
        return self._clean_fix_response(content)

    async def agent_fix(
        self,
        finding: Finding,
        model: Optional[str] = None,
        max_iterations: int = 5
    ) -> Dict[str, Any]:
        """
        Generate a fix using agentic approach with tool use.
        More accurate but slower - explores codebase as needed.

        Returns:
            Dict with 'fix' (the code) and 'reasoning' (steps taken)
        """
        self.scan_root = self._find_scan_root(finding)

        # Build initial context message
        initial_context = f"""=== VULNERABILITY TO FIX ===
Title: {finding.description}
Category: {finding.category or 'Unknown'}
Severity: {finding.severity}
File: {finding.file_path}
Line: {finding.line_number or 'Unknown'}

=== VULNERABLE CODE ===
{finding.snippet or '(No snippet available)'}

=== DETAILS ===
{finding.vulnerability_details or finding.description or ''}

Please analyze this vulnerability and use the available tools to gather context needed for an accurate fix.
When ready, output your fix wrapped in ```fix``` code blocks."""

        messages = [
            {"role": "system", "content": self.AGENT_SYSTEM_PROMPT},
            {"role": "user", "content": initial_context}
        ]

        reasoning_steps = []
        final_fix = ""

        def emit_step(iteration: int, step_type: str, tool_name: str = None, tool_args: str = None,
                      thought: str = None, result_preview: str = None, is_final: bool = False):
            """Emit a step event for streaming progress"""
            if self.step_callback:
                self.step_callback({
                    'step': iteration + 1,
                    'type': step_type,
                    'tool_name': tool_name,
                    'tool_args': tool_args,
                    'thought': thought,
                    'result_preview': result_preview[:200] if result_preview else None,
                    'is_final': is_final
                })

        for iteration in range(max_iterations):
            # Call LLM with tools
            result = await self._call_with_tools(messages, model)

            content = result.get("content", "")
            tool_calls = result.get("tool_calls", [])

            # Check if save_fix was called (diff_file_path will be set)
            if self.diff_file_path:
                reasoning_steps.append(f"Iteration {iteration + 1}: Fix saved via save_fix tool")
                emit_step(iteration, 'final_answer', thought="Fix saved successfully", is_final=True)
                break

            # Process tool calls
            if tool_calls:
                messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})

                for tool_call in tool_calls:
                    tool_name = tool_call.get("function", {}).get("name", "")
                    tool_args_raw = tool_call.get("function", {}).get("arguments", "{}")
                    tool_args = json.loads(tool_args_raw)

                    # Emit tool call step
                    emit_step(iteration, 'tool_call', tool_name=tool_name,
                             tool_args=tool_args_raw, thought=content[:300])

                    tool_result = await self._execute_tool(tool_name, tool_args)

                    reasoning_steps.append(f"Iteration {iteration + 1}: Called {tool_name}({tool_args})")

                    # Emit tool result step
                    emit_step(iteration, 'tool_result', tool_name=tool_name,
                             result_preview=tool_result)

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.get("id", ""),
                        "content": tool_result
                    })

                    # Check if save_fix was just called successfully
                    if tool_name == "save_fix" and "Fix saved successfully" in tool_result:
                        emit_step(iteration, 'final_answer', thought="Fix saved successfully", is_final=True)
                        break
            else:
                # No tools called - nudge to use save_fix
                messages.append({"role": "assistant", "content": content})
                messages.append({
                    "role": "user",
                    "content": "You must call save_fix with the complete fixed file content to submit your fix. Read the file first if you haven't, then call save_fix with the entire file content including your fix."
                })
                reasoning_steps.append(f"Iteration {iteration + 1}: Prompted to use save_fix")
                emit_step(iteration, 'thinking', thought=content[:300])

            # Exit if fix was saved
            if self.diff_file_path:
                break

        return {
            "fix": final_fix,  # Will be empty if save_fix was used (which is expected)
            "reasoning": reasoning_steps,
            "iterations": len(reasoning_steps),
            "diff_file": self.diff_file_path  # Path to saved diff file (if save_fix was used)
        }

    async def _call_with_tools(self, messages: List[Dict], model: Optional[str]) -> Dict[str, Any]:
        """Call LLM with tool definitions using centralized ModelPool with streaming"""
        from app.services.orchestration.model_orchestrator import ModelPool
        
        model_name = model or llm_provider.default_model

        try:
            # Use ModelPool's streaming method which handles timeouts/retries better
            return await ModelPool.simple_chat_with_tools(
                messages=messages,
                tools=self.AGENT_TOOLS,
                model=model_name,
                max_tokens=4096,
                tool_choice="auto"
            )
        except Exception as e:
            # Fall back to non-tool call if tools not supported
            result = await ModelPool.simple_chat_completion(
                messages=messages,
                model=model_name,
                max_tokens=4096
            )
            return {"content": result.get("content", ""), "tool_calls": []}

    async def _execute_tool(self, tool_name: str, args: Dict) -> str:
        """Execute a tool and return the result"""
        try:
            if tool_name == "read_file":
                return self._tool_read_file(args.get("path", ""))
            elif tool_name == "search_code":
                return self._tool_search_code(args.get("query", ""))
            elif tool_name == "list_files":
                return self._tool_list_files(args.get("directory", ""))
            elif tool_name == "save_fix":
                return await self._tool_save_fix(args.get("file_path", ""), args.get("diff", ""))
            else:
                return f"Unknown tool: {tool_name}"
        except Exception as e:
            return f"Error executing {tool_name}: {str(e)}"

    def _tool_read_file(self, path: str) -> str:
        """Read a file's contents"""
        # Resolve relative paths from scan root
        if self.scan_root and not os.path.isabs(path):
            full_path = os.path.join(self.scan_root, path)
        else:
            full_path = path

        if not os.path.exists(full_path):
            return f"File not found: {path}"

        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Truncate if too long
            if len(content) > 10000:
                return content[:10000] + f"\n\n... (truncated, {len(content)} total chars)"
            return content
        except Exception as e:
            return f"Error reading file: {e}"

    def _tool_search_code(self, query: str) -> str:
        """Search for code patterns in the codebase"""
        if not self.scan_root:
            return "No codebase root found for searching"

        results = []
        query_lower = query.lower()

        # Walk the codebase
        for root, dirs, files in os.walk(self.scan_root):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', 'venv', '.venv', 'build', 'dist']]

            for fname in files:
                # Only search code files
                if not any(fname.endswith(ext) for ext in ['.py', '.c', '.cpp', '.h', '.hpp', '.js', '.ts', '.java', '.go', '.rs']):
                    continue

                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()

                    for i, line in enumerate(lines):
                        if query_lower in line.lower():
                            rel_path = os.path.relpath(fpath, self.scan_root)
                            results.append(f"{rel_path}:{i+1}: {line.strip()[:100]}")

                            if len(results) >= 20:
                                break
                except:
                    continue

                if len(results) >= 20:
                    break

            if len(results) >= 20:
                break

        if not results:
            return f"No results found for: {query}"

        return "\n".join(results)

    def _tool_list_files(self, directory: str) -> str:
        """List files in a directory"""
        if self.scan_root and not os.path.isabs(directory):
            full_path = os.path.join(self.scan_root, directory)
        else:
            full_path = directory

        if not os.path.exists(full_path):
            return f"Directory not found: {directory}"

        if not os.path.isdir(full_path):
            return f"Not a directory: {directory}"

        try:
            entries = []
            for entry in os.listdir(full_path):
                entry_path = os.path.join(full_path, entry)
                if os.path.isdir(entry_path):
                    entries.append(f"[DIR] {entry}/")
                else:
                    entries.append(f"      {entry}")

            return "\n".join(sorted(entries)[:50])
        except Exception as e:
            return f"Error listing directory: {e}"

    async def _tool_save_fix(self, file_path: str, diff_content: str) -> str:
        """Save a unified diff directly to a .diff file.

        File naming: {original_file}.fix.{findingId}.{model}.diff
        If diff format is invalid, attempts cleanup using the cleanup model.
        """
        # Resolve the file path
        if self.scan_root and not os.path.isabs(file_path):
            full_path = os.path.join(self.scan_root, file_path)
        else:
            full_path = file_path

        if not os.path.exists(full_path):
            return f"Error: Original file not found: {file_path}"

        if not diff_content or not diff_content.strip():
            return "Error: Empty diff provided"

        try:
            # Basic validation - check for diff markers
            has_diff_markers = ('---' in diff_content and '+++' in diff_content) or '@@' in diff_content

            if not has_diff_markers:
                # Try cleanup model to fix the format
                cleaned = await self._cleanup_diff_format(diff_content, file_path)
                if cleaned:
                    diff_content = cleaned
                    has_diff_markers = ('---' in diff_content and '+++' in diff_content) or '@@' in diff_content

                if not has_diff_markers:
                    return "Error: Invalid diff format. Must include --- +++ headers or @@ hunk markers."

            # Generate diff file name: {file}.fix.{findingId}.{model}.diff
            model_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', self.model_name or 'unknown')
            diff_filename = f"{full_path}.fix.{self.finding_id}.{model_safe}.diff"

            # Write the diff file
            with open(diff_filename, 'w', encoding='utf-8') as f:
                f.write(diff_content)

            # Store the path for later reference
            self.diff_file_path = diff_filename

            # Count changes for summary
            additions = diff_content.count('\n+') - diff_content.count('\n+++')
            deletions = diff_content.count('\n-') - diff_content.count('\n---')

            return f"Fix saved successfully!\nDiff file: {diff_filename}\nChanges: +{additions} -{deletions} lines"

        except Exception as e:
            return f"Error saving fix: {str(e)}"

    async def _cleanup_diff_format(self, content: str, file_path: str) -> Optional[str]:
        """Use cleanup model to convert malformed diff into proper unified diff format."""
        try:
            from app.models.scanner_models import ModelConfig

            # Get cleanup model
            cleanup_model = self.db.query(ModelConfig).filter(ModelConfig.is_cleanup == True).first()
            if not cleanup_model:
                return None

            filename = os.path.basename(file_path)
            prompt = f"""Convert the following code fix into proper unified diff format.

The fix is for file: {filename}

INPUT (may be malformed or just code):
{content}

OUTPUT must be valid unified diff format like:
--- a/{filename}
+++ b/{filename}
@@ -LINE,COUNT +LINE,COUNT @@
 context line
-removed line
+added line
 context line

Rules:
- Lines starting with space are unchanged context
- Lines starting with - are removed
- Lines starting with + are added
- Include @@ header with approximate line numbers
- Output ONLY the diff, no explanation

Unified diff:"""

            result = await llm_provider.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                model=cleanup_model.name,
                max_tokens=2048
            )

            cleaned = result.get("content", "").strip()
            # Remove any markdown code blocks
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

            return cleaned if cleaned else None

        except Exception as e:
            print(f"Cleanup model failed: {e}")
            return None

    def _clean_fix_response(self, response: str) -> str:
        """Clean the fix response, removing thinking tags and markdown"""
        if not response:
            return ''

        text = response.strip()

        # Remove thinking tags
        text = re.sub(r'<thinking>.*?</thinking>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE)

        text = text.strip()

        # Remove markdown code blocks
        if text.startswith('```'):
            first_newline = text.find('\n')
            if first_newline != -1:
                text = text[first_newline + 1:]
            else:
                text = text[3:]

        if text.rstrip().endswith('```'):
            text = text.rstrip()[:-3]

        return text.strip()
