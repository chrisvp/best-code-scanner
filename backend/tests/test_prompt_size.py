"""
Test vLLM API with different prompt sizes to find limits.
"""
import asyncio
import httpx
import ssl

BASE_URL = "https://192.168.33.158:5000/v1"
API_KEY = "testkeyforchrisvp"

# Create SSL context that doesn't verify certificates
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


async def test_prompt(model: str, prompt: str, desc: str) -> dict:
    """Test a single prompt and return result."""
    print(f"\nTesting: {desc}")
    print(f"Prompt length: {len(prompt)} chars")

    async with httpx.AsyncClient(verify=False, timeout=120) as client:
        try:
            response = await client.post(
                f"{BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 500,
                    "temperature": 0.1
                }
            )

            if response.status_code == 200:
                data = response.json()
                content = data['choices'][0]['message']['content']
                print(f"SUCCESS: {content[:100]}...")
                return {"success": True, "response": content}
            else:
                print(f"ERROR {response.status_code}: {response.text[:200]}")
                return {"success": False, "error": response.text}

        except Exception as e:
            print(f"EXCEPTION: {e}")
            return {"success": False, "error": str(e)}


async def main():
    model = "mistral-small"

    # Test 1: Very small prompt
    await test_prompt(model, "Say hello", "Small prompt (10 chars)")

    # Test 2: Medium prompt (500 chars)
    medium = "Analyze this code for security vulnerabilities:\n```c\nint main() { return 0; }\n```\n" * 5
    await test_prompt(model, medium, f"Medium prompt ({len(medium)} chars)")

    # Test 3: Larger prompt (2000 chars)
    large = """You are a security expert analyzing code. Please review the following:

Code:
```c
int execute_hook(const char* hook_name) {
    char hook_path[256];
    char command[512];

    snprintf(hook_path, sizeof(hook_path), "/hooks/%s", hook_name);
    snprintf(command, sizeof(command), "/bin/sh %s", hook_path);

    int result = system(command);
    return result;
}
```

This code appears to have a command injection vulnerability. The hook_name parameter
is directly concatenated into a shell command without validation. An attacker could
provide a hook_name like "; rm -rf /" to execute arbitrary commands.

Please verify if this is a true vulnerability and explain the attack vector.
""" * 2
    await test_prompt(model, large, f"Large prompt ({len(large)} chars)")

    # Test 4: Agent-style prompt with tool descriptions
    agent_prompt = """You are a security expert analyzing code to verify potential vulnerabilities.
You have access to tools to explore the codebase. Use them to trace data flow and prove whether a vulnerability is real.

Available tools:

read_file: Read the contents of a file, optionally specifying line range
  Parameters:
    - path: File path (relative to scan root or absolute)
    - start_line: (optional) Starting line number (1-indexed)
    - end_line: (optional) Ending line number (inclusive)

find_definition: Find where a function, class, or variable is defined
  Parameters:
    - symbol: Name of the symbol to find (e.g., 'execute_hook', 'UserClass')

find_callers: Find all places that call a function
  Parameters:
    - function: Name of the function to find callers for

find_references: Find all uses of a symbol (variables, functions, classes)
  Parameters:
    - symbol: Name of the symbol to find references for

search_code: Search for a pattern across the codebase (grep-like)
  Parameters:
    - pattern: Regex pattern to search for
    - file_pattern: (optional) Glob pattern to filter files (e.g., '*.c')

trace_data_flow: Trace where a variable's value comes from (backward) or goes to (forward)
  Parameters:
    - variable: Name of the variable to trace
    - file: File where the variable is used
    - line: Line number where the variable appears
    - direction: 'backward' to find source, 'forward' to find sinks

find_entry_points: Find entry points where external input enters (network, file, CLI)
  Parameters: {}

To use a tool, format your response like this:
*TOOL_CALL*
name: <tool_name>
params: <json params>
*END_TOOL_CALL*

When you have enough information, provide your final answer in this format:
*FINAL_ANSWER*
VERDICT: VERIFIED or REJECTED
CONFIDENCE: 0-100
REASONING: Your explanation
ATTACK_PATH: (if verified) How an attacker would exploit this
*END_FINAL_ANSWER*

=== TASK ===
Verify this potential security vulnerability:

**Title:** Command Injection via Unvalidated Hook Execution
**Type:** CWE-78
**Severity:** Critical
**File:** firmware_updater.cpp
**Line:** 331

**Code:**
```
int result = system(command);
```

**Initial Assessment:** The hook_name argument is concatenated into hook_path without validation and then passed to system()

Your job is to determine if this is a TRUE vulnerability that is exploitable:

1. Use `find_callers` to see what calls this code
2. Use `trace_data_flow` to see where inputs come from
3. Use `find_entry_points` to identify if external input can reach this code
4. Use `read_file` to examine related code

Begin your analysis:"""

    await test_prompt(model, agent_prompt, f"Agent prompt ({len(agent_prompt)} chars)")

    # Test 5: Even larger (double the agent prompt)
    double_agent = agent_prompt + "\n\nAdditional context:\n" + agent_prompt
    await test_prompt(model, double_agent, f"Double agent prompt ({len(double_agent)} chars)")


if __name__ == "__main__":
    asyncio.run(main())
