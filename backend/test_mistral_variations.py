#!/usr/bin/env python3
"""
Test 10 different prompt variations on mistral-small to find optimal structure.

Focus: Different ordering, framing, and presentation styles.
"""

import json
import requests
import time
from datetime import datetime

# Ground truth test cases
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
    }
}

# 10 different prompt structures
PROMPT_VARIATIONS = {
    "v1_code_first": """```c
{code}
```

The scanner claims this has a vulnerability:
{claim}

Is this correct? Vote: FALSE_POSITIVE, REAL, NEEDS_VERIFIED, or WEAKNESS
Confidence: 0-100
Reasoning: [explain]""",

    "v2_verdict_first": """Vote on this vulnerability claim.

Your verdict options:
- FALSE_POSITIVE: Scanner is wrong, code is safe
- REAL: Confirmed exploitable vulnerability
- NEEDS_VERIFIED: Need more context
- WEAKNESS: Poor practice but not exploitable

Scanner's claim:
{claim}

Code:
```c
{code}
```

Vote: [category]
Confidence: [0-100]
Reasoning: [explain]""",

    "v3_numbered_steps": """Analyze this vulnerability report:

1. SCANNER'S CLAIM
{claim}

2. CODE UNDER REVIEW
```c
{code}
```

3. YOUR TASK
Determine if this is a real vulnerability.

4. OUTPUT FORMAT
Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [explanation]""",

    "v4_question_format": """Is this a real vulnerability?

Scanner says: {claim}

Code:
```c
{code}
```

Answer with:
Vote: FALSE_POSITIVE (safe) | REAL (exploitable) | NEEDS_VERIFIED (unclear) | WEAKNESS (not exploitable)
Confidence: 0-100
Reasoning: Why?""",

    "v5_checklist": """=== VULNERABILITY VERIFICATION ===

Code:
```c
{code}
```

Claim:
{claim}

Checklist:
□ Does the claimed vulnerability exist in the code?
□ Is it exploitable?
□ Are there mitigating factors?

Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [explain your checklist answers]""",

    "v6_expert_persona": """You are an expert UEFI firmware security auditor.

A junior analyst flagged this code:
```c
{code}
```

Their reasoning: {claim}

Are they correct? Provide your expert assessment.

Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [your expert analysis]""",

    "v7_minimal": """Code:
```c
{code}
```

Claim: {claim}

Vote: FALSE_POSITIVE | REAL | NEEDS_VERIFIED | WEAKNESS
Confidence: 0-100
Reasoning:""",

    "v8_context_last": """You are reviewing a security vulnerability report.

Vote categories:
- FALSE_POSITIVE: Code is safe, scanner is wrong
- REAL: Confirmed vulnerability, exploitable
- NEEDS_VERIFIED: Cannot confirm without more context
- WEAKNESS: Code quality issue, not directly exploitable

```c
{code}
```

Scanner's claim: {claim}

Vote:
Confidence:
Reasoning:""",

    "v9_bullet_points": """Vulnerability Report:

• Issue: {issue}
• Location: {file_path}:{line}
• Claim: {claim}

Code:
```c
{code}
```

Analysis:
• Vote: [FALSE_POSITIVE | REAL | NEEDS_VERIFIED | WEAKNESS]
• Confidence: [0-100]
• Reasoning: [explain]""",

    "v10_table_format": """| Field | Value |
|-------|-------|
| Issue | {issue} |
| Location | {file_path}:{line} |
| Claim | {claim} |

Code:
```c
{code}
```

Verdict:
| Vote | [FALSE_POSITIVE/REAL/NEEDS_VERIFIED/WEAKNESS] |
| Confidence | [0-100] |
| Reasoning | [explain] |"""
}

def call_llm(prompt: str, base_url: str = "https://davy.labs.lenovo.com:5000/v1") -> dict:
    """Call mistral-small via API."""
    try:
        response = requests.post(
            f"{base_url}/chat/completions",
            json={
                "model": "mistral-small",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 1000
            },
            headers={"Authorization": "Bearer testkeyforchrisvp"},
            verify=False,
            timeout=60
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def parse_vote(text: str) -> dict:
    """Extract vote, confidence, and reasoning."""
    import re

    # Strip thinking tags
    text_clean = re.sub(r'<thinking>.*?</thinking>', '', text, flags=re.DOTALL)
    text_clean = re.sub(r'<think>.*?</think>', '', text_clean, flags=re.DOTALL)

    vote = None
    confidence = None
    reasoning_lines = []

    # Look for vote
    vote_patterns = [
        r'Vote:\s*(\w+)',
        r'Verdict:\s*(\w+)',
        r'\|\s*Vote\s*\|\s*(\w+)',
    ]

    for pattern in vote_patterns:
        match = re.search(pattern, text_clean, re.IGNORECASE)
        if match:
            vote_text = match.group(1).upper().replace(' ', '_')
            for category in ['FALSE_POSITIVE', 'REAL', 'NEEDS_VERIFIED', 'WEAKNESS']:
                if category in vote_text or vote_text in category:
                    vote = category
                    break
            if vote:
                break

    # Fallback: look for keywords
    if not vote:
        if 'false positive' in text_clean.lower() or 'false_positive' in text_clean.lower():
            vote = 'FALSE_POSITIVE'
        elif re.search(r'\breal\b', text_clean.lower()):
            vote = 'REAL'
        elif 'needs_verified' in text_clean.lower() or 'needs verified' in text_clean.lower():
            vote = 'NEEDS_VERIFIED'
        elif 'weakness' in text_clean.lower():
            vote = 'WEAKNESS'

    # Look for confidence
    conf_patterns = [
        r'Confidence:\s*(\d+)',
        r'\|\s*Confidence\s*\|\s*(\d+)',
    ]

    for pattern in conf_patterns:
        match = re.search(pattern, text_clean)
        if match:
            try:
                confidence = int(match.group(1))
                break
            except:
                pass

    # Extract reasoning
    reasoning_match = re.search(r'Reasoning:\s*(.+?)(?:\n\n|$)', text_clean, re.DOTALL | re.IGNORECASE)
    if reasoning_match:
        reasoning_lines = [reasoning_match.group(1).strip()]
    else:
        reasoning_lines = [text_clean.strip()]

    return {
        "vote": vote,
        "confidence": confidence,
        "reasoning": '\n'.join(reasoning_lines)[:500],
        "raw_response": text
    }

def test_finding(finding_id: int, prompt_variant: str) -> dict:
    """Test one finding with one prompt variant."""
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
    print(f"Testing Finding {finding_id} with prompt variant '{prompt_variant}'")
    print(f"Ground truth: {truth['verdict']}")

    try:
        response = call_llm(prompt)

        if "error" in response:
            print(f"ERROR: {response['error']}")
            return {
                "finding_id": finding_id,
                "prompt_variant": prompt_variant,
                "error": response["error"],
                "timestamp": datetime.now().isoformat()
            }

        response_text = response['choices'][0]['message']['content']
        parsed = parse_vote(response_text)

        correct = parsed['vote'] == truth['verdict']

        print(f"{'✓' if correct else '✗'} Vote: {parsed['vote']} (confidence: {parsed['confidence']})")
        print(f"Reasoning: {parsed['reasoning'][:200]}...")

        return {
            "finding_id": finding_id,
            "prompt_variant": prompt_variant,
            "ground_truth": truth["verdict"],
            "model_vote": parsed["vote"],
            "confidence": parsed["confidence"],
            "correct": correct,
            "reasoning": parsed["reasoning"],
            "raw_response": response_text,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        print(f"ERROR: {e}")
        return {
            "finding_id": finding_id,
            "prompt_variant": prompt_variant,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def main():
    print("="*80)
    print("MISTRAL-SMALL PROMPT STRUCTURE TESTING")
    print("="*80)
    print(f"Findings: {list(GROUND_TRUTH.keys())}")
    print(f"Prompt variants: {len(PROMPT_VARIATIONS)}")
    print(f"Total tests: {len(GROUND_TRUTH) * len(PROMPT_VARIATIONS)}")
    print("="*80)

    results = []

    for finding_id in GROUND_TRUTH.keys():
        for prompt_variant in PROMPT_VARIATIONS.keys():
            result = test_finding(finding_id, prompt_variant)
            results.append(result)
            time.sleep(0.5)  # Rate limiting

    # Save results
    output_file = "/tmp/mistral_structure_test.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n{'='*80}")
    print("RESULTS SUMMARY")
    print("="*80)

    # Calculate accuracy by prompt
    accuracy_by_prompt = {}

    for result in results:
        if 'error' in result:
            continue

        prompt = result['prompt_variant']
        if prompt not in accuracy_by_prompt:
            accuracy_by_prompt[prompt] = {"correct": 0, "total": 0}

        accuracy_by_prompt[prompt]["total"] += 1
        if result['correct']:
            accuracy_by_prompt[prompt]["correct"] += 1

    print("\nAccuracy by Prompt Variant:")
    for prompt, stats in sorted(accuracy_by_prompt.items(),
                                key=lambda x: x[1]["correct"]/x[1]["total"] if x[1]["total"] > 0 else 0,
                                reverse=True):
        pct = 100 * stats["correct"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {prompt:20s}: {stats['correct']}/{stats['total']} ({pct:.1f}%)")

    print(f"\nFull results saved to: {output_file}")

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    main()
