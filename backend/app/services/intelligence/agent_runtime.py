"""
Agent runtime for multi-turn LLM interactions with tool use.
Enables agentic verification and interactive code exploration.
"""
import json
import re
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from app.services.intelligence.codebase_tools import CodebaseTools, ToolResult
from app.services.orchestration.model_orchestrator import ModelPool


class AgentState(Enum):
    """State of the agent execution"""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    MAX_STEPS_REACHED = "max_steps"


@dataclass
class AgentStep:
    """A single step in the agent's execution"""
    step_number: int
    thought: str
    tool_name: Optional[str] = None
    tool_params: Optional[Dict[str, Any]] = None
    tool_result: Optional[str] = None
    is_final: bool = False
    final_answer: Optional[str] = None


@dataclass
class AgentResult:
    """Result of an agent execution"""
    state: AgentState
    steps: List[AgentStep]
    final_answer: Optional[str]
    total_tokens: int = 0
    error: Optional[str] = None

    @property
    def trace(self) -> str:
        """Get a human-readable trace of the agent's execution"""
        lines = []
        for step in self.steps:
            lines.append(f"\n=== Step {step.step_number} ===")
            if step.thought:
                lines.append(f"Thought: {step.thought[:500]}")
            if step.tool_name:
                lines.append(f"Tool: {step.tool_name}({step.tool_params})")
                if step.tool_result:
                    lines.append(f"Result: {step.tool_result[:500]}...")
            if step.is_final:
                lines.append(f"Final Answer: {step.final_answer}")
        return "\n".join(lines)


class AgentRuntime:
    """
    Runtime for executing LLM agents with tool use.
    Implements a ReAct-style loop: Thought -> Action -> Observation
    """

    SYSTEM_PROMPT = """You are a security expert analyzing code to verify potential vulnerabilities.
You have access to tools to explore the codebase. Use them to trace data flow and prove whether a vulnerability is real.

{tool_descriptions}

When you have enough information, provide your final answer in this format:
*FINAL_ANSWER*
VERDICT: VERIFIED or REJECTED
CONFIDENCE: 0-100
REASONING: Your explanation
ATTACK_PATH: (if verified) How an attacker would exploit this
*END_FINAL_ANSWER*

Think step by step. Use tools to gather evidence before concluding."""

    TOOL_CALL_FORMAT = """To use a tool, format your response like this:
*TOOL_CALL*
name: <tool_name>
params: <json params>
*END_TOOL_CALL*

For example:
*TOOL_CALL*
name: read_file
params: {"path": "firmware_updater.cpp", "start_line": 320, "end_line": 340}
*END_TOOL_CALL*
"""

    def __init__(
        self,
        model_pool: ModelPool,
        tools: CodebaseTools,
        max_steps: int = 10,
        verbose: bool = False,
        scan_id: int = None,
        finding_id: int = None
    ):
        """
        Initialize the agent runtime.

        Args:
            model_pool: Model pool for LLM calls
            tools: CodebaseTools instance for code navigation
            max_steps: Maximum number of agent steps before stopping
            verbose: Whether to print debug info
            scan_id: Scan ID for logging context
            finding_id: Finding ID for logging context
        """
        self.model_pool = model_pool
        self.tools = tools
        self.max_steps = max_steps
        self.verbose = verbose
        self.scan_id = scan_id
        self.finding_id = finding_id

        # Set log context for the model pool
        if scan_id or finding_id:
            self.model_pool.set_log_context(
                scan_id=scan_id,
                phase='agent_verifier',
                analyzer_name=f'finding_{finding_id}' if finding_id else None
            )

    async def run(self, task: str, context: str = "") -> AgentResult:
        """
        Run the agent on a task.

        Args:
            task: The task/question for the agent
            context: Optional additional context

        Returns:
            AgentResult with the execution trace and final answer
        """
        steps: List[AgentStep] = []
        conversation = self._build_initial_prompt(task, context)

        for step_num in range(1, self.max_steps + 1):
            if self.verbose:
                print(f"\n--- Agent Step {step_num} ---")

            # Get LLM response
            try:
                response = await self.model_pool.call(conversation)
            except Exception as e:
                return AgentResult(
                    state=AgentState.FAILED,
                    steps=steps,
                    final_answer=None,
                    error=str(e)
                )

            # Parse the response
            step = self._parse_response(response, step_num)
            steps.append(step)

            if self.verbose:
                print(f"Thought: {step.thought[:200]}...")
                if step.tool_name:
                    print(f"Tool: {step.tool_name}")

            # Check for final answer
            if step.is_final:
                return AgentResult(
                    state=AgentState.COMPLETED,
                    steps=steps,
                    final_answer=step.final_answer
                )

            # Execute tool if requested
            if step.tool_name:
                result = self.tools.execute_tool(step.tool_name, step.tool_params or {})
                step.tool_result = result.to_string()

                if self.verbose:
                    print(f"Tool result: {step.tool_result[:200]}...")

                # Add to conversation
                conversation += f"\n\nAssistant: {response}\n\nTool Result ({step.tool_name}):\n{step.tool_result}\n\nContinue your analysis:"
            else:
                # No tool call and no final answer - prompt to continue
                conversation += f"\n\nAssistant: {response}\n\nPlease either use a tool to gather more information or provide your final answer."

        # Max steps reached
        return AgentResult(
            state=AgentState.MAX_STEPS_REACHED,
            steps=steps,
            final_answer=self._extract_best_answer(steps),
            error=f"Reached maximum {self.max_steps} steps"
        )

    def _build_initial_prompt(self, task: str, context: str) -> str:
        """Build the initial prompt for the agent"""
        tool_desc = self.tools.get_tool_descriptions()

        system = self.SYSTEM_PROMPT.format(tool_descriptions=tool_desc)
        system += "\n\n" + self.TOOL_CALL_FORMAT

        prompt = f"{system}\n\n"
        if context:
            prompt += f"=== CONTEXT ===\n{context}\n\n"
        prompt += f"=== TASK ===\n{task}\n\nBegin your analysis:"

        return prompt

    def _parse_response(self, response: str, step_num: int) -> AgentStep:
        """Parse an LLM response into an AgentStep"""
        step = AgentStep(step_number=step_num, thought="")

        # Check for final answer
        final_match = re.search(
            r'\*FINAL_ANSWER\*(.+?)\*END_FINAL_ANSWER\*',
            response,
            re.DOTALL | re.IGNORECASE
        )
        if final_match:
            step.is_final = True
            step.final_answer = final_match.group(1).strip()
            # Extract thought as everything before the final answer
            step.thought = response[:final_match.start()].strip()
            return step

        # Check for tool call
        tool_match = re.search(
            r'\*TOOL_CALL\*(.+?)\*END_TOOL_CALL\*',
            response,
            re.DOTALL | re.IGNORECASE
        )
        if tool_match:
            tool_block = tool_match.group(1)

            # Extract tool name
            name_match = re.search(r'name:\s*(\w+)', tool_block)
            if name_match:
                step.tool_name = name_match.group(1)

            # Extract params
            params_match = re.search(r'params:\s*(\{.+?\})', tool_block, re.DOTALL)
            if params_match:
                try:
                    step.tool_params = json.loads(params_match.group(1))
                except json.JSONDecodeError:
                    # Try to fix common issues
                    params_str = params_match.group(1)
                    # Replace single quotes with double quotes
                    params_str = params_str.replace("'", '"')
                    try:
                        step.tool_params = json.loads(params_str)
                    except:
                        step.tool_params = {}

            # Thought is everything before the tool call
            step.thought = response[:tool_match.start()].strip()
        else:
            # No tool call or final answer - whole response is thought
            step.thought = response.strip()

        return step

    def _extract_best_answer(self, steps: List[AgentStep]) -> Optional[str]:
        """Try to extract a useful answer from incomplete execution"""
        # Look for any reasoning in the last few steps
        for step in reversed(steps[-3:]):
            if step.thought and len(step.thought) > 100:
                return f"Analysis incomplete. Last reasoning:\n{step.thought}"
        return None


class AgenticVerifier:
    """
    Agentic verification of security findings.
    Uses the agent runtime to trace vulnerabilities and prove/disprove them.
    Pre-fetches relevant context to reduce model hallucinations.
    Stores detailed session logs for debugging and analysis.
    """

    VERIFICATION_TASK = """Verify this potential security vulnerability:

**Title:** {title}
**Type:** {vuln_type}
**Severity:** {severity}
**File:** {file_path}
**Line:** {line_number}

**Reported Code Snippet:**
```
{snippet}
```

**Initial Assessment:** {reason}

=== PRE-FETCHED CONTEXT (DO NOT SEARCH FOR THESE - ALREADY PROVIDED) ===

**Available files in codebase:**
{file_list}

**Full file content ({file_path}):**
```
{file_content}
```

**Callers of this code:**
{callers}

=== END PRE-FETCHED CONTEXT ===

Your job is to determine if this is a TRUE vulnerability that could be exploitable.
You may use tools to gather ADDITIONAL context (e.g., trace data flow, read other files).

CRITICAL: Missing a real vulnerability is FAR WORSE than a false positive. When in doubt, VERIFY.

VERIFY (mark as True Positive) if ANY of these apply:
- The dangerous code pattern exists (system(), sprintf to fixed buffer, use-after-free, format string without specifier, etc.)
- User/external input COULD reach this code path (even indirectly or in future code changes)
- The function is exported/public and could be called with malicious input
- There's no validation, or validation could be bypassed
- You're uncertain whether it's exploitable - VERIFY to be safe

REJECT (mark as False Positive) ONLY if you can PROVE ALL of these:
- The exact vulnerability pattern reported does NOT exist in the code, OR
- There is MATHEMATICALLY PROVEN bounds checking that cannot be bypassed, OR
- The code is 100% dead (no callers, not exported, impossible to reach)

Examples that should be VERIFIED even if "currently safe":
- A function using system() that currently only gets hardcoded strings - VERIFY (future caller could pass user input)
- A buffer copy that currently fits - VERIFY (buffer sizes could change)
- A format string from a config file - VERIFY (config could be attacker-controlled)

Be thorough but efficient. Focus on analyzing the pre-fetched context first."""

    def __init__(
        self,
        model_pool: ModelPool,
        tools: CodebaseTools,
        max_steps: int = 8,
        scan_id: int = None,
        finding_id: int = None
    ):
        self.model_pool = model_pool
        self.tools = tools
        self.max_steps = max_steps
        self.scan_id = scan_id
        self.finding_id = finding_id
        self.runtime = AgentRuntime(
            model_pool, tools, max_steps=max_steps,
            scan_id=scan_id, finding_id=finding_id
        )

    def _prefetch_context(self, file_path: str, snippet: str, line_number: int) -> Dict[str, str]:
        """
        Pre-fetch relevant context to include in the prompt.
        This reduces the need for the model to search/read files.
        """
        context = {
            'file_list': '',
            'file_content': '',
            'callers': ''
        }

        # Get list of files in codebase
        files_result = self.tools.list_files()
        if files_result.success:
            context['file_list'] = files_result.data[:2000]  # Limit size

        # Read the full file content (or around the line if file is large)
        file_result = self.tools.read_file(file_path)
        if file_result.success:
            content = file_result.data
            # If file is huge, just get context around the line
            if len(content) > 10000 and line_number > 0:
                # Get 100 lines around the target
                file_result = self.tools.read_file(file_path, max(1, line_number - 50), line_number + 50)
                if file_result.success:
                    context['file_content'] = file_result.data
                else:
                    context['file_content'] = content[:10000] + "\n... (truncated)"
            else:
                context['file_content'] = content
        else:
            # Try fuzzy match
            context['file_content'] = f"File not found: {file_path}\nError: {file_result.error}"

        # Find callers - extract function name from snippet if possible
        import re
        # Try to find function being called in the snippet
        func_patterns = [
            r'(\w+)\s*\(',  # function call
            r'(\w+)\s*=',   # assignment target
        ]
        func_name = None
        for pattern in func_patterns:
            match = re.search(pattern, snippet)
            if match:
                func_name = match.group(1)
                # Skip common keywords
                if func_name not in ['if', 'for', 'while', 'return', 'int', 'char', 'void']:
                    break
                func_name = None

        if func_name:
            callers_result = self.tools.find_callers(func_name)
            if callers_result.success:
                context['callers'] = callers_result.data[:3000]  # Limit size
            else:
                context['callers'] = f"No callers found for '{func_name}'"
        else:
            context['callers'] = "(Could not extract function name from snippet)"

        return context

    async def verify(
        self,
        title: str,
        vuln_type: str,
        severity: str,
        file_path: str,
        line_number: int,
        snippet: str,
        reason: str,
        draft_finding_id: int = None
    ) -> Dict[str, Any]:
        """
        Verify a single finding using agentic exploration.

        Returns:
            Dict with verification result:
            - verified: bool
            - confidence: int (0-100)
            - reasoning: str
            - attack_path: str (if verified)
            - trace: str (execution trace)
            - session_id: int (database session ID)
        """
        import time
        from datetime import datetime
        start_time = time.time()

        # Pre-fetch context to spoon-feed the model
        prefetched = self._prefetch_context(file_path, snippet, line_number)

        task = self.VERIFICATION_TASK.format(
            title=title,
            vuln_type=vuln_type,
            severity=severity,
            file_path=file_path,
            line_number=line_number,
            snippet=snippet,
            reason=reason,
            file_list=prefetched['file_list'],
            file_content=prefetched['file_content'],
            callers=prefetched['callers']
        )

        # Create session log in database
        session_id = None
        try:
            from app.core.database import SessionLocal
            from app.models.scanner_models import AgentVerificationSession
            db = SessionLocal()
            session = AgentVerificationSession(
                scan_id=self.scan_id,
                finding_id=self.finding_id,
                draft_finding_id=draft_finding_id,
                status="running",
                model_name=self.model_pool.config.name if self.model_pool.config else "unknown",
                max_steps=self.max_steps,
                task_prompt=task[:10000],  # Truncate if too long
                prefetched_context={
                    'file_list': prefetched['file_list'][:1000],
                    'file_content_length': len(prefetched['file_content']),
                    'callers': prefetched['callers'][:1000]
                }
            )
            db.add(session)
            db.commit()
            session_id = session.id
            db.close()
        except Exception as e:
            print(f"Failed to create agent session log: {e}")

        result = await self.runtime.run(task)

        # Parse the final answer
        verification = self._parse_verification(result)
        verification['trace'] = result.trace
        verification['state'] = result.state.value

        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000

        # Update session log with results
        if session_id:
            try:
                db = SessionLocal()
                session = db.query(AgentVerificationSession).filter(
                    AgentVerificationSession.id == session_id
                ).first()
                if session:
                    session.status = result.state.value
                    session.verdict = "VERIFIED" if verification['verified'] else "REJECTED"
                    session.confidence = verification['confidence']
                    session.reasoning = verification.get('reasoning', '')[:5000]
                    session.attack_path = verification.get('attack_path', '')[:2000]
                    session.total_steps = len(result.steps)
                    session.total_tokens = result.total_tokens
                    session.duration_ms = duration_ms
                    session.execution_trace = [
                        {
                            'step': s.step_number,
                            'thought': s.thought[:2000] if s.thought else None,
                            'tool_name': s.tool_name,
                            'tool_params': s.tool_params,
                            'tool_result': s.tool_result[:1000] if s.tool_result else None,
                            'is_final': s.is_final
                        }
                        for s in result.steps
                    ]
                    session.completed_at = datetime.utcnow()
                    if result.error:
                        session.error_message = result.error
                    db.commit()
                db.close()
            except Exception as e:
                print(f"Failed to update agent session log: {e}")

        verification['session_id'] = session_id
        return verification

    def _parse_verification(self, result: AgentResult) -> Dict[str, Any]:
        """Parse the agent result into a verification dict"""
        default = {
            'verified': False,
            'confidence': 50,
            'reasoning': 'Analysis incomplete',
            'attack_path': ''
        }

        if not result.final_answer:
            if result.error:
                default['reasoning'] = f"Error: {result.error}"
            return default

        answer = result.final_answer.upper()

        # Extract verdict
        if 'VERIFIED' in answer or 'TRUE POSITIVE' in answer:
            default['verified'] = True
        elif 'REJECTED' in answer or 'FALSE POSITIVE' in answer:
            default['verified'] = False

        # Extract confidence
        conf_match = re.search(r'CONFIDENCE:\s*(\d+)', result.final_answer, re.IGNORECASE)
        if conf_match:
            default['confidence'] = min(100, int(conf_match.group(1)))

        # Extract reasoning
        reason_match = re.search(
            r'REASONING:\s*(.+?)(?:ATTACK_PATH:|$)',
            result.final_answer,
            re.DOTALL | re.IGNORECASE
        )
        if reason_match:
            default['reasoning'] = reason_match.group(1).strip()

        # Extract attack path
        path_match = re.search(
            r'ATTACK_PATH:\s*(.+?)(?:\*END|$)',
            result.final_answer,
            re.DOTALL | re.IGNORECASE
        )
        if path_match:
            default['attack_path'] = path_match.group(1).strip()

        return default


class InteractiveAgent:
    """
    Interactive agent for chat-based code exploration.
    Allows users to ask questions about the codebase.
    """

    SYSTEM_PROMPT = """You are a security expert assistant helping analyze a codebase.
You can explore the code using these tools to answer questions about security, architecture, and implementation.

{tool_descriptions}

Be helpful, thorough, and security-focused. When asked about vulnerabilities, trace data flow and provide evidence.

Format tool calls like this:
*TOOL_CALL*
name: <tool_name>
params: <json params>
*END_TOOL_CALL*

When you have a complete answer:
*ANSWER*
<your answer here>
*END_ANSWER*
"""

    def __init__(
        self,
        model_pool: ModelPool,
        tools: CodebaseTools,
        max_steps: int = 15
    ):
        self.runtime = AgentRuntime(model_pool, tools, max_steps=max_steps, verbose=False)
        self.conversation_history: List[Dict[str, str]] = []

    async def chat(self, user_message: str) -> str:
        """
        Process a user message and return a response.

        Args:
            user_message: The user's question or request

        Returns:
            The assistant's response
        """
        self.conversation_history.append({"role": "user", "content": user_message})

        # Build context from history
        context = "\n".join([
            f"{'User' if m['role'] == 'user' else 'Assistant'}: {m['content']}"
            for m in self.conversation_history[-10:]  # Last 10 messages
        ])

        result = await self.runtime.run(user_message, context)

        response = result.final_answer or result.trace
        self.conversation_history.append({"role": "assistant", "content": response})

        return response

    def reset(self):
        """Reset the conversation history"""
        self.conversation_history = []
