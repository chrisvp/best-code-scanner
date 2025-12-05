"""
Fix generation service with Quick Fix and Agent Fix modes.

Quick Fix: Single-shot LLM call with full file context
Agent Fix: Multi-turn agentic approach with tool use
"""
import os
import re
import json
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session

from app.models.models import Finding, Scan
from app.services.llm_provider import llm_provider


class FixGenerator:
    """Generates security vulnerability fixes using LLM"""

    QUICK_FIX_PROMPT = """You are a security expert fixing a vulnerability. Generate the corrected code.

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

=== INSTRUCTIONS ===
1. Analyze the vulnerable code in context of the full file
2. Generate ONLY the corrected code that fixes the vulnerability
3. Maintain the same coding style and conventions
4. Include necessary imports if adding new dependencies
5. Output only the fixed code, no explanations

Provide the corrected code:"""

    AGENT_SYSTEM_PROMPT = """You are a security expert tasked with fixing a vulnerability. You have tools to explore the codebase.

Your goal: Generate an accurate, production-ready fix for the security vulnerability.

TOOLS AVAILABLE:
- read_file(path): Read a file's contents
- search_code(query): Search for code patterns in the codebase
- list_files(directory): List files in a directory

APPROACH:
1. First understand the vulnerability and its context
2. Use tools to gather necessary context (imports, related functions, type definitions)
3. Generate a fix that integrates properly with the codebase
4. Verify the fix addresses the root cause, not just the symptom

When you have enough context, output your final fix in this format:
```fix
<your corrected code here>
```

Start by analyzing what context you need."""

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
        }
    ]

    def __init__(self, db: Session):
        self.db = db
        self.scan_root = None  # Root directory of the scanned code

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

        for iteration in range(max_iterations):
            # Call LLM with tools
            result = await self._call_with_tools(messages, model)

            content = result.get("content", "")
            tool_calls = result.get("tool_calls", [])

            # Check if we have a final fix
            fix_match = re.search(r'```fix\s*([\s\S]*?)```', content)
            if fix_match:
                final_fix = fix_match.group(1).strip()
                reasoning_steps.append(f"Iteration {iteration + 1}: Generated final fix")
                break

            # Process tool calls
            if tool_calls:
                messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})

                for tool_call in tool_calls:
                    tool_name = tool_call.get("function", {}).get("name", "")
                    tool_args = json.loads(tool_call.get("function", {}).get("arguments", "{}"))
                    tool_result = await self._execute_tool(tool_name, tool_args)

                    reasoning_steps.append(f"Iteration {iteration + 1}: Called {tool_name}({tool_args})")

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.get("id", ""),
                        "content": tool_result
                    })
            else:
                # No tools called and no fix - add a nudge
                messages.append({"role": "assistant", "content": content})
                messages.append({
                    "role": "user",
                    "content": "Please either use a tool to gather more context, or output your fix in ```fix``` blocks."
                })
                reasoning_steps.append(f"Iteration {iteration + 1}: Prompted for action")

        # If we didn't get a fix, try to extract any code from the last response
        if not final_fix and content:
            code_match = re.search(r'```(?:\w+)?\s*([\s\S]*?)```', content)
            if code_match:
                final_fix = code_match.group(1).strip()

        return {
            "fix": self._clean_fix_response(final_fix),
            "reasoning": reasoning_steps,
            "iterations": len(reasoning_steps)
        }

    async def _call_with_tools(self, messages: List[Dict], model: Optional[str]) -> Dict[str, Any]:
        """Call LLM with tool definitions"""
        client = llm_provider.get_client()
        model_name = model or llm_provider.default_model

        try:
            response = await client.chat.completions.create(
                model=model_name,
                messages=messages,
                tools=self.AGENT_TOOLS,
                tool_choice="auto",
                max_tokens=4096
            )

            choice = response.choices[0] if response.choices else None
            if not choice:
                return {"content": "", "tool_calls": []}

            message = choice.message
            return {
                "content": message.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments
                        }
                    }
                    for tc in (message.tool_calls or [])
                ]
            }
        except Exception as e:
            # Fall back to non-tool call if tools not supported
            result = await llm_provider.chat_completion(
                messages=messages,
                model=model,
                max_tokens=4096
            )
            return {"content": result.get("content", ""), "tool_calls": []}
        finally:
            await client.close()

    async def _execute_tool(self, tool_name: str, args: Dict) -> str:
        """Execute a tool and return the result"""
        try:
            if tool_name == "read_file":
                return self._tool_read_file(args.get("path", ""))
            elif tool_name == "search_code":
                return self._tool_search_code(args.get("query", ""))
            elif tool_name == "list_files":
                return self._tool_list_files(args.get("directory", ""))
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
