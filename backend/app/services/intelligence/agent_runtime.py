"""
Agent runtime for multi-turn LLM interactions with tool use.
Enables agentic verification and interactive code exploration.
"""
import json
import re
import asyncio
from typing import List, Dict, Optional, Any, Callable, AsyncGenerator, Literal
from dataclasses import dataclass, field
from enum import Enum

from app.services.intelligence.codebase_tools import CodebaseTools, ToolResult
from app.services.orchestration.model_orchestrator import ModelPool

# JSON schema for agent responses (used with guided_json mode)
AGENT_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "thinking": {"type": "string", "description": "Your analysis and reasoning"},
        "action": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["tool_call", "final_answer"]},
                "tool_name": {"type": "string"},
                "tool_params": {"type": "object"},
                "answer": {"type": "string"}
            },
            "required": ["type"]
        }
    },
    "required": ["thinking", "action"]
}


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

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'step': self.step_number,
            'thought': self.thought[:500] if self.thought else None,
            'tool_name': self.tool_name,
            'tool_params': self.tool_params,
            'tool_result': self.tool_result[:500] if self.tool_result else None,
            'is_final': self.is_final
        }


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

    # Minimum number of tool uses before allowing final answer
    MIN_TOOL_USES = 2

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

    # JSON mode format instruction
    JSON_FORMAT = """You MUST respond in valid JSON format. Your response must be a single JSON object.

For tool calls:
{"thinking": "your analysis...", "action": {"type": "tool_call", "tool_name": "read_file", "tool_params": {"path": "file.c", "start_line": 100}}}

For final answer:
{"thinking": "your reasoning...", "action": {"type": "final_answer", "answer": "VERDICT: VERIFIED\\nCONFIDENCE: 85\\nREASONING: ...\\nATTACK_PATH: ..."}}

Always output ONLY valid JSON with no additional text before or after.
"""

    def __init__(
        self,
        model_pool: ModelPool,
        tools: CodebaseTools,
        max_steps: int = 10,
        min_tool_uses: int = 2,
        verbose: bool = False,
        scan_id: int = None,
        finding_id: int = None,
        step_callback: Optional[Callable[[AgentStep], None]] = None,
        response_format: Literal["markers", "json", "json_schema"] = "markers"
    ):
        """
        Initialize the agent runtime.

        Args:
            model_pool: Model pool for LLM calls
            tools: CodebaseTools instance for code navigation
            max_steps: Maximum number of agent steps before stopping
            min_tool_uses: Minimum tool uses before allowing final answer
            verbose: Whether to print debug info
            scan_id: Scan ID for logging context
            finding_id: Finding ID for logging context
            step_callback: Optional callback called after each step (for streaming)
            response_format: Output format - 'markers' (text), 'json', or 'json_schema' (vLLM guided)
        """
        self.model_pool = model_pool
        self.tools = tools
        self.max_steps = max_steps
        self.min_tool_uses = min_tool_uses
        self.verbose = verbose
        self.scan_id = scan_id
        self.finding_id = finding_id
        self.tool_use_count = 0  # Track tool usage
        self.step_callback = step_callback
        self.response_format = response_format

        # Set log context for the model pool
        if scan_id or finding_id:
            self.model_pool.set_log_context(
                scan_id=scan_id,
                phase='agent_verifier',
                analyzer_name=f'finding_{finding_id}' if finding_id else None
            )

    async def _call_llm(self, prompt: str) -> str:
        """Make LLM call with appropriate output format."""
        if self.response_format in ("json", "json_schema"):
            # Use call_batch for JSON modes to pass output_mode
            output_mode = "json" if self.response_format == "json" else "guided_json"
            json_schema = json.dumps(AGENT_JSON_SCHEMA) if self.response_format == "json_schema" else None
            results = await self.model_pool.call_batch(
                [prompt],
                output_mode=output_mode,
                json_schema=json_schema
            )
            return results[0] if results else ""
        else:
            # Use regular call for text-based markers format
            return await self.model_pool.call(prompt)

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
        self.tool_use_count = 0  # Reset for this run
        retry_count = 0
        max_retries = 1  # Allow one retry for malformed tool calls

        for step_num in range(1, self.max_steps + 1):
            if self.verbose:
                print(f"\n--- Agent Step {step_num} ---")

            # Get LLM response
            try:
                response = await self._call_llm(conversation)
            except Exception as e:
                return AgentResult(
                    state=AgentState.FAILED,
                    steps=steps,
                    final_answer=None,
                    error=str(e)
                )

            # Parse the response
            step = self._parse_response(response, step_num)

            if self.verbose:
                print(f"Thought: {step.thought[:200]}..." if step.thought else "No thought")
                if step.tool_name:
                    print(f"Tool: {step.tool_name}")

            # Check for final answer - but enforce minimum tool usage first
            if step.is_final:
                if self.tool_use_count < self.min_tool_uses:
                    # Not enough tools used - ignore final answer and prompt for more investigation
                    if self.verbose:
                        print(f"Final answer rejected: only {self.tool_use_count}/{self.min_tool_uses} tools used")
                    step.is_final = False
                    step.final_answer = None
                    conversation += f"\n\nAssistant: {response}\n\nYou must use at least {self.min_tool_uses} tools before providing a final answer. You have only used {self.tool_use_count}. Please use a tool to investigate further."
                    steps.append(step)
                    if self.step_callback:
                        self.step_callback(step)
                    continue
                else:
                    steps.append(step)
                    if self.step_callback:
                        self.step_callback(step)
                    return AgentResult(
                        state=AgentState.COMPLETED,
                        steps=steps,
                        final_answer=step.final_answer
                    )

            steps.append(step)
            if self.step_callback:
                self.step_callback(step)

            # Execute tool if requested
            if step.tool_name:
                # Check if tool params failed to parse - retry once
                if step.tool_name and step.tool_params is None and retry_count < max_retries:
                    retry_count += 1
                    conversation += f"\n\nAssistant: {response}\n\nError: Your tool call had invalid or missing JSON parameters. Please try again with valid JSON in this format:\n*TOOL_CALL*\nname: {step.tool_name}\nparams: {{\"key\": \"value\"}}\n*END_TOOL_CALL*"
                    continue

                result = self.tools.execute_tool(step.tool_name, step.tool_params or {})
                step.tool_result = self._format_tool_result(result)
                self.tool_use_count += 1
                retry_count = 0  # Reset retry count on successful tool use

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

    def _format_tool_result(self, result) -> str:
        """Format tool result with better error messages."""
        if result.success:
            return result.to_string()

        # Enhance error messages for common issues
        error = result.error or "Unknown error"

        if "Unmatched" in error or "regex" in error.lower():
            return f"Error: Invalid regex pattern. Special characters like (, ), [, ], {{, }} need to be escaped with backslash. Try a simpler pattern or escape special chars.\nOriginal error: {error}"

        if "not found" in error.lower():
            return f"Error: {error}\nTip: Use list_files to see available files, or search_code to find the right file."

        if "permission" in error.lower():
            return f"Error: {error}\nThe file may not be accessible."

        return f"Error: {error}"

    def _build_initial_prompt(self, task: str, context: str) -> str:
        """Build the initial prompt for the agent"""
        tool_desc = self.tools.get_tool_descriptions()

        system = self.SYSTEM_PROMPT.format(tool_descriptions=tool_desc)

        # Use JSON format instructions for json modes, otherwise use markers
        if self.response_format in ("json", "json_schema"):
            system += "\n\n" + self.JSON_FORMAT
        else:
            system += "\n\n" + self.TOOL_CALL_FORMAT

        prompt = f"{system}\n\n"
        if context:
            prompt += f"=== CONTEXT ===\n{context}\n\n"
        prompt += f"=== TASK ===\n{task}\n\nBegin your analysis:"

        return prompt

    def _parse_response(self, response: str, step_num: int) -> AgentStep:
        """Parse an LLM response into an AgentStep.

        IMPORTANT: Tool calls are prioritized over final answers.
        If both are present, execute the tool first - the model should iterate.
        """
        step = AgentStep(step_number=step_num, thought="")

        # Try JSON parsing first for json response_format modes
        if self.response_format in ("json", "json_schema"):
            json_step = self._parse_json_response(response, step_num)
            if json_step:
                return json_step
            # Fall through to markers parsing if JSON parse fails

        # Check for tool call FIRST - always execute tools before conclusions
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

            # Extract params - try multiple formats
            params_match = re.search(r'params:\s*(\{.+?\})', tool_block, re.DOTALL)
            if params_match:
                try:
                    step.tool_params = json.loads(params_match.group(1))
                except json.JSONDecodeError:
                    # Try to fix common issues
                    params_str = params_match.group(1)
                    params_str = params_str.replace("'", '"')
                    try:
                        step.tool_params = json.loads(params_str)
                    except:
                        step.tool_params = {}

            # Thought is everything before the tool call
            step.thought = response[:tool_match.start()].strip()
            return step  # Return immediately - execute tool before any final answer

        # Only check for final answer if NO tool calls
        final_match = re.search(
            r'\*FINAL_ANSWER\*(.+?)\*END_FINAL_ANSWER\*',
            response,
            re.DOTALL | re.IGNORECASE
        )
        if final_match:
            step.is_final = True
            step.final_answer = final_match.group(1).strip()
            step.thought = response[:final_match.start()].strip()
            return step

        # No tool call or final answer - whole response is thought
        step.thought = response.strip()
        return step

    def _parse_json_response(self, response: str, step_num: int) -> Optional[AgentStep]:
        """Parse a JSON-formatted agent response.

        Expected format:
        {
            "thinking": "analysis and reasoning...",
            "action": {
                "type": "tool_call" | "final_answer",
                "tool_name": "...",  // for tool_call
                "tool_params": {...},  // for tool_call
                "answer": "..."  // for final_answer
            }
        }
        """
        try:
            # Try to extract JSON from response (may have extra text around it)
            json_match = re.search(r'\{[\s\S]*\}', response)
            if not json_match:
                return None

            data = json.loads(json_match.group(0))

            step = AgentStep(step_number=step_num, thought="")
            step.thought = data.get("thinking", "")

            action = data.get("action", {})
            action_type = action.get("type", "")

            if action_type == "tool_call":
                step.tool_name = action.get("tool_name")
                step.tool_params = action.get("tool_params", {})
            elif action_type == "final_answer":
                step.is_final = True
                step.final_answer = action.get("answer", "")

            return step
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            if self.verbose:
                print(f"JSON parse error: {e}")
            return None

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
    Stores detailed session logs for debugging and analysis.
    """

    VERIFICATION_TASK = """You are verifying a potential security vulnerability. Your goal is to INVESTIGATE using tools before reaching any conclusion.

## Finding to Verify
- **Title:** {title}
- **Type:** {vuln_type}
- **Severity:** {severity}
- **File:** {file_path}
- **Line:** {line_number}
- **Snippet:** `{snippet}`
- **Initial Assessment:** {reason}

## YOUR TASK

You MUST use tools to investigate this finding. Do NOT provide a final answer until you have:
1. Read the actual code around line {line_number} in {file_path}
2. Traced data flow to find where inputs come from
3. Checked for callers or entry points

## IMPORTANT RULES

1. **USE TOOLS FIRST** - You must use at least 2-3 tools before concluding
2. **ONE ACTION PER STEP** - Either use a tool OR give a final answer, never both
3. **INVESTIGATE THOROUGHLY** - Don't assume anything, verify with actual code

## Suggested Investigation Steps

Step 1: Use `read_file` to see the code around line {line_number}
Step 2: Use `trace_data_flow` or `find_callers` to understand input sources
Step 3: Use `get_call_graph` or `find_entry_points` if needed

## Verdict Guidelines

**VERIFY** (True Positive) if ANY apply:
- Dangerous pattern exists (system(), sprintf to fixed buffer, use-after-free, format string)
- User input could reach this code path
- Function is exported/public
- No validation or bypassable validation

**REJECT** (False Positive) ONLY if you PROVE ALL:
- Pattern does NOT exist in actual code
- Mathematically proven bounds checking
- Code is 100% unreachable

When in doubt, VERIFY. Missing a real vulnerability is worse than a false positive.

## START NOW

Begin by using the `read_file` tool to examine the code. Do NOT provide your final answer yet."""

    def __init__(
        self,
        model_pool: ModelPool,
        tools: CodebaseTools,
        max_steps: int = 8,
        scan_id: int = None,
        finding_id: int = None,
        response_format: Literal["markers", "json", "json_schema"] = "markers"
    ):
        self.model_pool = model_pool
        self.tools = tools
        self.max_steps = max_steps
        self.scan_id = scan_id
        self.finding_id = finding_id
        self.response_format = response_format
        self.runtime = AgentRuntime(
            model_pool, tools, max_steps=max_steps,
            scan_id=scan_id, finding_id=finding_id,
            response_format=response_format
        )

    def _get_available_files(self) -> str:
        """Get a brief list of available files for context."""
        files_result = self.tools.list_files()
        if files_result.success:
            return files_result.data[:1500]  # Brief list only
        return "Unable to list files"

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

        # Build task with minimal context - let agent discover via tools
        available_files = self._get_available_files()

        task = self.VERIFICATION_TASK.format(
            title=title,
            vuln_type=vuln_type,
            severity=severity,
            file_path=file_path,
            line_number=line_number,
            snippet=snippet,
            reason=reason
        )

        # Add available files as context (but not file content)
        context = f"Available files in codebase:\n{available_files}"

        # Create session log in database
        session_id = None
        try:
            from app.core.database import SessionLocal
            from app.models.scanner_models import AgentSession
            db = SessionLocal()
            session = AgentSession(
                scan_id=self.scan_id,
                finding_id=self.finding_id,
                draft_finding_id=draft_finding_id,
                status="running",
                model_name=self.model_pool.config.name if self.model_pool.config else "unknown",
                max_steps=self.max_steps,
                task_prompt=task[:10000],  # Truncate if too long
                prefetched_context={
                    'available_files': available_files[:1000]
                }
            )
            db.add(session)
            db.commit()
            session_id = session.id
            db.close()
        except Exception as e:
            print(f"Failed to create agent session log: {e}")

        result = await self.runtime.run(task, context)

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
                session = db.query(AgentSession).filter(
                    AgentSession.id == session_id
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
