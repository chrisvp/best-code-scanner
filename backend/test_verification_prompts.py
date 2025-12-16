#!/usr/bin/env python3
"""
Test different verification prompt variations against the same findings
to measure impact on model accuracy.

Usage:
    python test_verification_prompts.py
    python test_verification_prompts.py --finding 221
    python test_verification_prompts.py --model gpt-oss-120b
"""

import json
import sqlite3
import requests
from typing import Dict, List, Optional
import argparse
from datetime import datetime

# Ground truth for test cases
GROUND_TRUTH = {
    221: {
        "verdict": "FALSE_POSITIVE",
        "file_path": "/home/aiadmin/web-davy-code-scanner/backend/sandbox/3/BootManagerDxe/Legacy.c",
        "line": 4450,
        "issue": "Integer Overflow in Legacy Option ROM Size Calculation",
        "code": """ImageSize = ((EFI_LEGACY_EXPANSION_ROM_HEADER *)((UINT8 *)LocalRomImage))->Size512 * 512;

PhysicalAddress = CONVENTIONAL_MEMORY_TOP;
Status = (gBS->AllocatePages) (
           AllocateMaxAddress,
           EfiBootServicesCode,
           EFI_SIZE_TO_PAGES (ImageSize),
           &PhysicalAddress);

if (EFI_ERROR (Status)) {
  FreePool (HandleBuffer);
  return EFI_OUT_OF_RESOURCES;
}

InitAddress = (UINTN)PhysicalAddress;
CopyMem ((VOID *)InitAddress, LocalRomImage, ImageSize);""",
        "claim": "Size512 is a 16-bit field; multiplying by 512 can overflow a 32-bit UINTN, causing ImageSize to be smaller than the actual ROM size and resulting in a buffer overflow when CopyMem copies ImageSize bytes into the allocated buffer.",
        "reasoning": "Size512 max value is 65,535. Multiplication: 65,535 * 512 = 33,553,920 bytes (~32 MB). UINTN on 32-bit systems: max 4GB. UINTN on 64-bit systems: max 18+ exabytes. No overflow possible. ImageSize is declared as UINTN."
    },
    213: {
        "verdict": "REAL",
        "file_path": "/home/aiadmin/web-davy-code-scanner/backend/sandbox/3/BootManagerDxe/BootManager.c",
        "line": 1791,
        "issue": "Out-of-bounds read of NVRAM variable structure",
        "code": """SctLibGetVariable(
           PBA_STATUS_VAR_NAME,
           &PbaStatusVarGuid,
           &Attributes,
           &VarSize,
           (VOID**)&PbaStatusVar);

if (EFI_ERROR (Status) || VarSize == 0) {
  DPRINTF ("Failed to get PBA_STATUS_VAR_NAME variable, status: %r.\\n", Status);
  return SCT_STATUS_INVALID_DATA;
}

if (PbaStatusVar->IdentifyOnBoot != 0) {
  if (mBmHotkeySupport_Count != 0) {
    UPDATE_HOTKEY_STATES (mTextInEx);
  }""",
        "claim": "The code retrieves a variable PbaStatusVar using SctLibGetVariable. While it checks VarSize != 0, it doesn't verify if VarSize is large enough to hold a PBA_STATUS_VAR structure before dereferencing PbaStatusVar->IdentifyOnBoot.",
        "reasoning": "UEFI GetVariable() returns whatever size the variable was set to. If an attacker manipulates NVRAM to make the variable 1 byte, the code will still dereference PbaStatusVar->IdentifyOnBoot, reading beyond allocated memory. The check VarSize != 0 is insufficient - it should check VarSize >= sizeof(PBA_STATUS_VAR)."
    },
    215: {
        "verdict": "REAL",
        "file_path": "/home/aiadmin/web-davy-code-scanner/backend/sandbox/3/BootManagerDxe/BootManager.c",
        "line": 1972,
        "issue": "Out-of-bounds read / improper size check on EFI_OS_INDICATIONS variable",
        "code": """SctLibGetVariable(
           L"OsIndications",
           &gEfiGlobalVariableGuid,
           NULL,
           &DataSize,
           (VOID **) &OsIndications);

if (!EFI_ERROR (Status)) {
  //
  // Always clear EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED bit if it has
  // been set.  It indicate the capsule is delivered through ESP.
  //

  if (*OsIndications & EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED) {
    mCapsuleEspDelivery = TRUE;
    *OsIndications &= ~EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED;
  }""",
        "claim": "The code assumes the EFI variable 'OsIndications' is exactly a UINT64; it never verifies that DataSize returned by SctLibGetVariable matches sizeof(UINT64) before dereferencing, allowing a malformed variable to cause an out-of-bounds read.",
        "reasoning": "SctLibGetVariable allocates a buffer sized to the actual variable data (DataSize). The code dereferences *OsIndications as a UINT64 without verifying DataSize >= sizeof(UINT64). If the NVRAM variable is smaller (e.g., 2 bytes), this causes an out-of-bounds read."
    }
}

# Prompt variations to test
PROMPT_VARIATIONS = {
    "original": """You are an expert security auditor reviewing a potential vulnerability report.

=== VULNERABILITY CLAIM ===
{issue}
File: {file_path}:{line}

{claim}

=== CODE TO REVIEW ===
```c
{code}
```

=== YOUR TASK ===
Determine if this is a real vulnerability or a false positive.

Vote must be one of: FALSE_POSITIVE, REAL, NEEDS_VERIFIED, WEAKNESS

Vote meanings:
- FALSE_POSITIVE: Scanner mistake, code is safe
- REAL: Confirmed exploitable vulnerability with visible evidence
- NEEDS_VERIFIED: Cannot confirm without seeing more code
- WEAKNESS: Poor practice but not directly exploitable

Respond in this format:
Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [your explanation]""",

    "math_focus": """You are a security expert analyzing a vulnerability report. Your analysis should be mathematically rigorous.

=== REPORTED ISSUE ===
{issue}
Location: {file_path}:{line}

Scanner's claim:
{claim}

=== CODE ===
```c
{code}
```

=== INSTRUCTIONS ===
1. If the issue involves numeric calculations, PERFORM THE ACTUAL MATH
2. State assumptions explicitly (e.g., data type sizes, platform architecture)
3. Calculate maximum/minimum values for any arithmetic operations
4. Verify if claimed overflows/underflows are mathematically possible

Vote categories:
- FALSE_POSITIVE: Code is safe (if math proves no overflow/underflow possible)
- REAL: Exploitable vulnerability (with evidence)
- NEEDS_VERIFIED: Need more information
- WEAKNESS: Code quality issue, not exploitable

Respond in this exact format:
Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [detailed mathematical reasoning]""",

    "adversarial": """You are a security researcher trying to exploit this code.

=== TARGET ===
{issue}
File: {file_path}:{line}

A scanner reported:
{claim}

=== CODE ===
```c
{code}
```

=== YOUR TASK ===
Think like an attacker. Can you actually exploit this?

1. What inputs can you control?
2. What values would trigger the vulnerability?
3. Can you bypass any checks?
4. Does the math actually allow an exploit?

BE SKEPTICAL. Many scanner reports are false positives. Prove the exploit is possible or disprove it.

Vote options:
- REAL: You can demonstrate a concrete exploit path
- FALSE_POSITIVE: No exploit possible (explain why)
- NEEDS_VERIFIED: Need to see more code to determine exploitability
- WEAKNESS: Poor coding but not exploitable

Respond in this exact format:
Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [your explanation]""",

    "assume_unsafe": """You are reviewing a security vulnerability report. ASSUME CODE IS UNSAFE UNLESS PROVEN SAFE.

=== ISSUE ===
{issue}
{file_path}:{line}

{claim}

=== CODE ===
```c
{code}
```

=== VERIFICATION CHECKLIST ===
Does the code:
□ Validate all input sizes?
□ Check array bounds before access?
□ Validate pointer dereferences?
□ Handle integer overflow/underflow?
□ Sanitize external data?

If ANY check is missing, vote REAL unless you have concrete evidence the check exists elsewhere or isn't needed.

DO NOT assume frameworks provide safety guarantees unless you can cite the specific guarantee.

Respond in this exact format:
Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [explain which checks are missing or present]""",

    "assume_safe": """You are reviewing a security vulnerability report from an automated scanner.

Automated scanners produce MANY false positives. Your job is to filter out false alarms.

=== SCANNER REPORT ===
{issue}
{file_path}:{line}

{claim}

=== CODE ===
```c
{code}
```

=== VERIFICATION APPROACH ===
1. Does the code actually exhibit the flaw the scanner describes?
2. Are there protections the scanner missed (type sizes, validation elsewhere, framework guarantees)?
3. Is the claimed exploit mathematically possible?
4. Could this be a scanner heuristic false positive?

ONLY vote REAL if you can demonstrate a concrete exploit with specific values.

Respond in this exact format:
Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [explain]""",

    "uefi_expert": """You are a UEFI firmware security expert analyzing a vulnerability report.

=== REPORT ===
{issue}
Location: {file_path}:{line}

{claim}

=== CODE ===
```c
{code}
```

=== UEFI-SPECIFIC CONTEXT ===
Consider:
- UEFI variable services (GetVariable/SetVariable) behavior
- UEFI memory management (AllocatePages, AllocatePool)
- Standard UEFI data types (UINTN, EFI_STATUS, etc.)
- UEFI specification guarantees vs. implementation-defined behavior
- Attack surface: Can attacker control NVRAM? Variable contents? Sizes?

DO NOT assume UEFI provides safety guarantees it doesn't actually provide.
UEFI GetVariable returns whatever size was stored - it does NOT enforce structure sizes.

Respond in this exact format:
Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [cite UEFI specification where relevant]""",

    "show_work": """You are a security analyst reviewing a vulnerability.

=== VULNERABILITY ===
{issue}
{file_path}:{line}

{claim}

=== CODE ===
```c
{code}
```

=== INSTRUCTIONS ===
Show your work step-by-step:

STEP 1: Identify claimed vulnerability type
[write here]

STEP 2: Identify relevant variables and their types
[write here]

STEP 3: Trace data flow / calculate values
[write here]

STEP 4: Determine if exploit is possible
[write here]

STEP 5: Final verdict
Vote: FALSE_POSITIVE | REAL | NEEDS_VERIFIED | WEAKNESS
Confidence: 0-100
Reasoning: [summary]"""
}


def call_llm(model: str, prompt: str, base_url: str = "https://davy.labs.lenovo.com:5000/v1") -> Dict:
    """Call LLM via OpenAI-compatible API."""
    response = requests.post(
        f"{base_url}/chat/completions",
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 1000
        },
        headers={"Authorization": "Bearer testkeyforchrisvp"},
        verify=False
    )
    response.raise_for_status()
    return response.json()


def parse_vote(text: str) -> Dict:
    """Extract vote, confidence, and reasoning from response."""
    # Strip thinking tags if present
    import re
    text_clean = re.sub(r'<thinking>.*?</thinking>', '', text, flags=re.DOTALL)
    text_clean = re.sub(r'<think>.*?</think>', '', text_clean, flags=re.DOTALL)

    lines = text_clean.strip().split('\n')
    vote = None
    confidence = None
    reasoning_lines = []

    in_reasoning = False

    for line in lines:
        line_lower = line.lower().strip()

        # Extract vote
        if 'vote:' in line_lower or 'verdict:' in line_lower:
            for category in ['FALSE_POSITIVE', 'REAL', 'NEEDS_VERIFIED', 'WEAKNESS']:
                if category.lower() in line_lower or category.replace('_', ' ').lower() in line_lower:
                    vote = category
                    break

        # Extract confidence
        if 'confidence' in line_lower:
            # Look for percentage or number
            numbers = re.findall(r'\d+', line)
            if numbers:
                try:
                    confidence = int(numbers[0])
                except:
                    pass

        # Collect reasoning
        if 'reasoning:' in line_lower:
            in_reasoning = True
            reasoning_lines.append(line.split(':', 1)[1].strip() if ':' in line else '')
        elif in_reasoning:
            reasoning_lines.append(line)

    # Fallback: look for vote keywords anywhere in text
    if vote is None:
        if 'false positive' in text_clean.lower() or 'false_positive' in text_clean.lower():
            vote = 'FALSE_POSITIVE'
        elif re.search(r'\breal\b', text_clean.lower()):
            vote = 'REAL'
        elif 'needs_verified' in text_clean.lower() or 'needs verified' in text_clean.lower():
            vote = 'NEEDS_VERIFIED'
        elif 'weakness' in text_clean.lower():
            vote = 'WEAKNESS'

    # Fallback reasoning: use everything after thinking tags
    if not reasoning_lines:
        reasoning_lines = [text_clean.strip()]

    return {
        "vote": vote,
        "confidence": confidence,
        "reasoning": '\n'.join(reasoning_lines).strip(),
        "raw_response": text
    }


def test_finding(finding_id: int, model: str, prompt_variant: str, base_url: str) -> Dict:
    """Test a single finding with a specific prompt variant."""
    truth = GROUND_TRUTH[finding_id]
    prompt_template = PROMPT_VARIATIONS[prompt_variant]

    prompt = prompt_template.format(
        issue=truth["issue"],
        file_path=truth["file_path"],
        line=truth["line"],
        claim=truth["claim"],
        code=truth["code"]
    )

    print(f"\n{'='*80}")
    print(f"Testing Finding {finding_id} with {model} using '{prompt_variant}' prompt")
    print(f"{'='*80}")
    print(f"Ground truth: {truth['verdict']}")
    print(f"Reasoning: {truth['reasoning'][:200]}...")
    print(f"\nCalling LLM...")

    try:
        response = call_llm(model, prompt, base_url)
        response_text = response['choices'][0]['message']['content']
        parsed = parse_vote(response_text)

        correct = parsed['vote'] == truth['verdict']

        result = {
            "finding_id": finding_id,
            "model": model,
            "prompt_variant": prompt_variant,
            "ground_truth": truth["verdict"],
            "model_vote": parsed["vote"],
            "confidence": parsed["confidence"],
            "correct": correct,
            "reasoning": parsed["reasoning"],
            "raw_response": response_text,
            "timestamp": datetime.now().isoformat()
        }

        print(f"\n{'✓' if correct else '✗'} Model vote: {parsed['vote']} (confidence: {parsed['confidence']})")
        print(f"Reasoning: {parsed['reasoning'][:300]}...")

        return result

    except Exception as e:
        print(f"ERROR: {e}")
        return {
            "finding_id": finding_id,
            "model": model,
            "prompt_variant": prompt_variant,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


def main():
    parser = argparse.ArgumentParser(description="Test verification prompt variations")
    parser.add_argument("--finding", type=int, choices=[221, 213, 215],
                       help="Test specific finding (default: all)")
    parser.add_argument("--model", type=str,
                       help="Test specific model (default: all)")
    parser.add_argument("--prompt", type=str, choices=list(PROMPT_VARIATIONS.keys()),
                       help="Test specific prompt variant (default: all)")
    parser.add_argument("--base-url", type=str,
                       default="https://davy.labs.lenovo.com:5000/v1",
                       help="LLM API base URL")
    parser.add_argument("--output", type=str, default="/tmp/verification_test_results.json",
                       help="Output file for results")

    args = parser.parse_args()

    # Determine test matrix
    findings = [args.finding] if args.finding else list(GROUND_TRUTH.keys())

    # Get models from database if not specified
    if args.model:
        models = [args.model]
    else:
        conn = sqlite3.connect('data/scans.db')
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT name FROM model_configs WHERE is_verifier = 1")
        models = [row[0] for row in cursor.fetchall()]
        conn.close()

    prompts = [args.prompt] if args.prompt else list(PROMPT_VARIATIONS.keys())

    print(f"\n{'='*80}")
    print(f"TEST MATRIX")
    print(f"{'='*80}")
    print(f"Findings: {findings}")
    print(f"Models: {models}")
    print(f"Prompt variants: {prompts}")
    print(f"Total tests: {len(findings) * len(models) * len(prompts)}")
    print(f"{'='*80}\n")

    results = []

    for finding_id in findings:
        for model in models:
            for prompt_variant in prompts:
                result = test_finding(finding_id, model, prompt_variant, args.base_url)
                results.append(result)

    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n{'='*80}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*80}")

    # Calculate accuracy by model and prompt
    accuracy_by_model = {}
    accuracy_by_prompt = {}

    for result in results:
        if 'error' in result:
            continue

        model = result['model']
        prompt = result['prompt_variant']
        correct = result['correct']

        if model not in accuracy_by_model:
            accuracy_by_model[model] = {"correct": 0, "total": 0}
        if prompt not in accuracy_by_prompt:
            accuracy_by_prompt[prompt] = {"correct": 0, "total": 0}

        accuracy_by_model[model]["total"] += 1
        accuracy_by_prompt[prompt]["total"] += 1

        if correct:
            accuracy_by_model[model]["correct"] += 1
            accuracy_by_prompt[prompt]["correct"] += 1

    print("\nAccuracy by Model:")
    for model, stats in sorted(accuracy_by_model.items()):
        pct = 100 * stats["correct"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {model}: {stats['correct']}/{stats['total']} ({pct:.1f}%)")

    print("\nAccuracy by Prompt Variant:")
    for prompt, stats in sorted(accuracy_by_prompt.items(),
                                key=lambda x: x[1]["correct"]/x[1]["total"] if x[1]["total"] > 0 else 0,
                                reverse=True):
        pct = 100 * stats["correct"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {prompt}: {stats['correct']}/{stats['total']} ({pct:.1f}%)")

    print(f"\nFull results saved to: {args.output}")


if __name__ == "__main__":
    main()
