#!/usr/bin/env python3
"""
Comprehensive test runner for llama3.3-70b-instruct model
Tests 1 model × 20 prompts × 13 findings = 260 tests

Usage:
    python run_llama_comprehensive_test.py [--base-url URL]

Result saved to: /tmp/comprehensive_results/llama3.3-70b-instruct_results.json
"""

import json
import requests
import sys
import re
from typing import Dict, List, Tuple
from datetime import datetime
from pathlib import Path

# Test findings (13 total: 3 original + 10 new)
TEST_FINDINGS = {
    # Original 3 test cases
    221: {
        "verdict": "FALSE_POSITIVE",
        "file_path": "BootManagerDxe/Legacy.c",
        "line": 4450,
        "issue": "Integer Overflow in ROM Size Calculation",
        "code": """ImageSize = ((EFI_LEGACY_EXPANSION_ROM_HEADER *)((UINT8 *)LocalRomImage))->Size512 * 512;
PhysicalAddress = CONVENTIONAL_MEMORY_TOP;
Status = (gBS->AllocatePages)(AllocateMaxAddress, EfiBootServicesCode, EFI_SIZE_TO_PAGES(ImageSize), &PhysicalAddress);
if (EFI_ERROR(Status)) { FreePool(HandleBuffer); return EFI_OUT_OF_RESOURCES; }
InitAddress = (UINTN)PhysicalAddress;
CopyMem((VOID *)InitAddress, LocalRomImage, ImageSize);""",
        "claim": "Size512 is 16-bit; multiplying by 512 can overflow 32-bit UINTN, causing ImageSize smaller than actual ROM size, resulting in buffer overflow."
    },

    213: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/BootManager.c",
        "line": 1791,
        "issue": "Out-of-bounds read of NVRAM variable",
        "code": """SctLibGetVariable(PBA_STATUS_VAR_NAME, &PbaStatusVarGuid, &Attributes, &VarSize, (VOID**)&PbaStatusVar);
if (EFI_ERROR(Status) || VarSize == 0) {
  return SCT_STATUS_INVALID_DATA;
}
if (PbaStatusVar->IdentifyOnBoot != 0) {
  UPDATE_HOTKEY_STATES(mTextInEx);
}""",
        "claim": "Code checks VarSize != 0 but doesn't verify VarSize >= sizeof(PBA_STATUS_VAR) before dereferencing."
    },

    215: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/BootManager.c",
        "line": 1972,
        "issue": "Missing UINT64 size check on OsIndications",
        "code": """SctLibGetVariable(L"OsIndications", &gEfiGlobalVariableGuid, NULL, &DataSize, (VOID **)&OsIndications);
if (!EFI_ERROR(Status)) {
  if (*OsIndications & EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED) {
    mCapsuleEspDelivery = TRUE;
    *OsIndications &= ~EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED;
  }
}""",
        "claim": "Code assumes OsIndications is UINT64 but never verifies DataSize == sizeof(UINT64) before dereferencing."
    },

    # 10 new test cases from scan #13
    211: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/BootManager.c",
        "line": 1279,
        "issue": "Missing size validation for BootNext variable",
        "code": """Status = GetBootOption(*BootNextValue, &Option);
if (EFI_ERROR(Status) || Option == NULL) {
  // handle error
}""",
        "claim": "Code assumes BootNext variable contains at least UINT16 and dereferences without size confirmation."
    },

    216: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/BootManager.c",
        "line": 4138,
        "issue": "Null pointer dereference in image sorting",
        "code": """for (i = HandleCount - 1; i > 0; i--) {
  for (j = 0; j < i; j++) {
    if ((ImagePackage[j])->ZValue > (ImagePackage[j + 1])->ZValue) {
      Temp = ImagePackage[j];
      ImagePackage[j] = ImagePackage[j + 1];
      ImagePackage[j + 1] = Temp;
    }
  }
}""",
        "claim": "ImagePackage[j] may be NULL if OpenProtocol failed; code dereferences without null-check."
    },

    218: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/BootManager.c",
        "line": 192,
        "issue": "Uninitialized function pointer usage",
        "code": """return Item->mOldPciIoAttributes(This, Operation, Attributes, Result);""",
        "claim": "mOldPciIoAttributes only set when Pci->Attributes != PciIoAttributesFilter; otherwise remains uninitialized."
    },

    220: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/Legacy.c",
        "line": 1366,
        "issue": "OOB write to IdeDiskInfo array",
        "code": """IbvBbs->IdeDiskInfo[IdeInfo].DiskInfoDeviceType = BBS_IDE_HDD_DEVICE_TYPE;""",
        "claim": "IdeInfo incremented without bounds check against IdeDiskInfo array size."
    },

    223: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/Legacy.c",
        "line": 1665,
        "issue": "OOB access of HddInfo array",
        "code": """if (((HddInfo[HddInfoIndex].Status & HDD_PRIMARY) != 0) ...) { ... }""",
        "claim": "HddInfoIndex derived from BbsOrder without bounds checking."
    },

    230: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/Legacy.c",
        "line": 4193,
        "issue": "NULL pointer dereference when querying SMI",
        "code": """Status = SwSmiAllocator->QuerySwSmi(&mCsmSwSmiGuidArray[SCT_CSM_LEGACY_USB_BY_IRQ], &CsmSwSmiInputValue);""",
        "claim": "SwSmiAllocator may be NULL if protocol lookup fails."
    },

    232: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/Legacy.c",
        "line": 5338,
        "issue": "OOB write to BbsTable arrays",
        "code": """BbsTableDevicePaths[i] = DuplicateDevicePath(DevicePath);
BbsTable[i].BootPriority = BBS_UNPRIORITIZED_ENTRY;""",
        "claim": "Index i derived from device ranges but equals BbsCount, allowing writes past allocated tables."
    },

    233: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/Legacy.c",
        "line": 5486,
        "issue": "OOB access via unchecked buffer index",
        "code": """if (BbsTableDevicePaths[Buffer[Index]] != NULL) { ... }""",
        "claim": "Buffer[Index] used as array index without bounds verification."
    },

    234: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/BootManager.c",
        "line": 5939,
        "issue": "Integer overflow in OptionalDataLength calculation",
        "code": """*OptionalDataLength += (UINT32)GetDevicePathSize(*DevicePath);""",
        "claim": "GetDevicePathSize() can return large value; adding without overflow check may wrap size."
    },

    235: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/BootManager.c",
        "line": 1049,
        "issue": "Integer overflow / infinite loop in boot-option lookup",
        "code": """for (j = 0; j < (mProtectedBootOptionsSize / sizeof(UINT16)); j++) { ... }""",
        "claim": "Loop counter j is UINT16; if size exceeds 0xFFFF × 2 bytes, comparison wraps and loop never terminates."
    },
}

# 20 prompt variations (10 original + 10 new)
PROMPTS = {
    # Original 10 from structure testing
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

Scanner's claim: {claim}

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

Claim: {claim}

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
| Reasoning | [explain] |""",

    # 10 NEW DRASTICALLY DIFFERENT STYLES

    "v11_socratic": """I will ask you questions to help determine if this is a vulnerability.

Code:
```c
{code}
```

Claim: {claim}

Questions:
1. Can you identify where the potential issue occurs?
2. What values would trigger this issue?
3. Can an attacker control those values?
4. What is the impact if exploited?
5. Are there any protections in place?

Based on your answers:
Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [explain]""",

    "v12_red_team": """RED TEAM EXERCISE: Try to exploit this code.

```c
{code}
```

Scanner allegation: {claim}

Your mission: Prove or disprove exploitability.
- If you can craft an attack: Vote REAL
- If attack is impossible: Vote FALSE_POSITIVE
- If you need more info: Vote NEEDS_VERIFIED
- If it's bad code but not exploitable: Vote WEAKNESS

Vote:
Confidence:
Attack scenario (or why it's safe):""",

    "v13_diff_format": """--- BEFORE (Scanner's View) ---
VULNERABLE: {claim}

--- ACTUAL CODE ---
```c
{code}
```

--- ANALYSIS ---
Compare the scanner's claim to the actual code.

Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [explain discrepancy or agreement]""",

    "v14_emoji_visual": """🔍 SECURITY ANALYSIS

📄 Code:
```c
{code}
```

⚠️ Scanner Alert: {claim}

🤔 Your Assessment:
• Vote: [FALSE_POSITIVE | REAL | NEEDS_VERIFIED | WEAKNESS]
• Confidence: [0-100]
• Reasoning: [explain]""",

    "v15_json_structured": """{{
  "code": ```{code}```,
  "scanner_claim": "{claim}",
  "your_analysis": {{
    "vote": "[FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]",
    "confidence": 0-100,
    "reasoning": "[explain]"
  }}
}}

Fill in your_analysis based on the code review.""",

    "v16_markdown_report": """# Vulnerability Assessment Report

## Code Under Review
```c
{code}
```

## Scanner Findings
{claim}

## Analysis

### Severity Assessment
Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]

### Confidence Level
[0-100]

### Detailed Reasoning
[Your analysis here]""",

    "v17_xml_format": """<vulnerability-analysis>
  <code>{code}</code>
  <claim>{claim}</claim>
  <assessment>
    <vote>[FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]</vote>
    <confidence>[0-100]</confidence>
    <reasoning>[explain]</reasoning>
  </assessment>
</vulnerability-analysis>""",

    "v18_prose": """Review the following code snippet and determine whether the scanner's vulnerability claim is accurate.

The code in question is:
{code}

The scanner believes there is a security issue, specifically: {claim}

Provide your professional security assessment. State whether you believe this is a false positive, a real vulnerability, requires further verification, or is merely a weakness. Include your confidence level (0-100) and explain your reasoning in detail.

Your assessment:""",

    "v19_adversarial_skeptic": """SKEPTICAL REVIEW: Assume the scanner is probably wrong.

Code:
```c
{code}
```

Scanner (likely mistaken) says: {claim}

Your job: Find reasons why this is a FALSE POSITIVE.
- Look for protections the scanner missed
- Consider framework guarantees
- Check if math makes the claim impossible

Only vote REAL if you cannot find any reason to dismiss this claim.

Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Reasoning: [explain why scanner is wrong, or admit it's right]""",

    "v20_chain_of_thought": """Let's think through this step-by-step.

Code:
```c
{code}
```

Claim: {claim}

Step 1: Identify what the code does
[Your analysis]

Step 2: Locate the alleged vulnerability
[Your analysis]

Step 3: Determine if it's exploitable
[Your analysis]

Step 4: Consider mitigations
[Your analysis]

Conclusion:
Vote: [FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS]
Confidence: [0-100]
Final reasoning: [summary]"""
}


def call_llm(model: str, prompt: str, base_url: str) -> Dict:
    """Call LLM via OpenAI-compatible API."""
    try:
        response = requests.post(
            f"{base_url}/chat/completions",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 1000,
                "timeout": 60
            },
            headers={"Authorization": "Bearer testkeyforchrisvp"},
            verify=False,
            timeout=120
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        raise Exception(f"API timeout (120s)")
    except requests.exceptions.RequestException as e:
        raise Exception(f"API error: {e}")


def parse_vote(text: str) -> Dict:
    """Extract vote, confidence, and reasoning from response."""
    # Strip thinking tags if present
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
            numbers = re.findall(r'\d+', line)
            if numbers:
                try:
                    confidence = int(numbers[0])
                    if confidence > 100:
                        confidence = 100
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
        "reasoning": '\n'.join(reasoning_lines).strip()[:500],
        "raw_response": text
    }


def test_finding(finding_id: int, model: str, prompt_variant: str, base_url: str, test_num: int, total_tests: int) -> Dict:
    """Test a single finding with a specific prompt variant."""
    truth = TEST_FINDINGS[finding_id]
    prompt_template = PROMPTS[prompt_variant]

    prompt = prompt_template.format(
        issue=truth["issue"],
        file_path=truth["file_path"],
        line=truth["line"],
        claim=truth["claim"],
        code=truth["code"]
    )

    try:
        response = call_llm(model, prompt, base_url)
        response_text = response['choices'][0]['message']['content']
        parsed = parse_vote(response_text)

        correct = parsed['vote'] == truth['verdict']

        result = {
            "test_num": test_num,
            "total_tests": total_tests,
            "finding_id": finding_id,
            "model": model,
            "prompt_variant": prompt_variant,
            "ground_truth": truth["verdict"],
            "model_vote": parsed["vote"],
            "confidence": parsed["confidence"],
            "correct": correct,
            "reasoning": parsed["reasoning"],
            "timestamp": datetime.now().isoformat()
        }

        # Print progress
        status = "PASS" if correct else "FAIL"
        print(f"[{test_num:3d}/{total_tests}] {status} | F:{finding_id:3d} | {prompt_variant:20s} | Vote: {parsed['vote']:15s} | Conf: {parsed['confidence'] or 0:3} | Ground: {truth['verdict']}")

        return result

    except Exception as e:
        print(f"[{test_num:3d}/{total_tests}] ERROR | F:{finding_id:3d} | {prompt_variant:20s} | {str(e)[:50]}")
        return {
            "test_num": test_num,
            "total_tests": total_tests,
            "finding_id": finding_id,
            "model": model,
            "prompt_variant": prompt_variant,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


def main():
    # Configuration
    MODEL = "llama3.3-70b-instruct"
    BASE_URL = "https://davy.labs.lenovo.com:5000/v1"

    if len(sys.argv) > 1:
        if sys.argv[1].startswith("--base-url="):
            BASE_URL = sys.argv[1].split("=", 1)[1]
        elif sys.argv[1] == "--base-url" and len(sys.argv) > 2:
            BASE_URL = sys.argv[2]

    # Create output directory
    output_dir = Path("/tmp/comprehensive_results")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Test matrix
    findings = sorted(TEST_FINDINGS.keys())
    prompts = list(PROMPTS.keys())

    total_tests = len(findings) * len(prompts)
    results = []

    print("=" * 120)
    print(f"COMPREHENSIVE LLAMA3.3-70B-INSTRUCT TESTING")
    print("=" * 120)
    print(f"Model: {MODEL}")
    print(f"Base URL: {BASE_URL}")
    print(f"Findings: {len(findings)}")
    print(f"Prompts: {len(prompts)}")
    print(f"Total tests: {total_tests}")
    print("=" * 120)
    print()

    test_num = 0
    for finding_id in findings:
        for prompt_variant in prompts:
            test_num += 1
            result = test_finding(finding_id, MODEL, prompt_variant, BASE_URL, test_num, total_tests)
            results.append(result)

    # Save results
    output_file = output_dir / f"{MODEL}_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Calculate statistics
    print()
    print("=" * 120)
    print("TEST EXECUTION COMPLETED")
    print("=" * 120)

    successful_tests = [r for r in results if 'error' not in r]
    failed_tests = [r for r in results if 'error' in r]
    correct_tests = [r for r in successful_tests if r.get('correct', False)]

    print(f"Total tests: {len(results)}")
    print(f"Successful: {len(successful_tests)}")
    print(f"Errors: {len(failed_tests)}")
    print(f"Correct votes: {len(correct_tests)}")
    accuracy = len(correct_tests) / len(successful_tests) if successful_tests else 0
    print(f"Accuracy: {100 * accuracy:.1f}%")

    # Per-prompt accuracy
    print()
    print("Accuracy by Prompt Variant:")
    print("-" * 80)
    by_prompt = {}
    for r in successful_tests:
        prompt = r['prompt_variant']
        if prompt not in by_prompt:
            by_prompt[prompt] = {"correct": 0, "total": 0}
        by_prompt[prompt]["total"] += 1
        if r['correct']:
            by_prompt[prompt]["correct"] += 1

    for prompt in sorted(by_prompt.keys()):
        stats = by_prompt[prompt]
        pct = 100 * stats["correct"] / stats["total"]
        print(f"  {prompt:20s}: {stats['correct']:2d}/{stats['total']:2d} ({pct:5.1f}%)")

    # Per-finding accuracy
    print()
    print("Accuracy by Finding:")
    print("-" * 80)
    by_finding = {}
    for r in successful_tests:
        finding = r['finding_id']
        if finding not in by_finding:
            by_finding[finding] = {"correct": 0, "total": 0}
        by_finding[finding]["total"] += 1
        if r['correct']:
            by_finding[finding]["correct"] += 1

    for finding in sorted(by_finding.keys()):
        stats = by_finding[finding]
        pct = 100 * stats["correct"] / stats["total"]
        truth = TEST_FINDINGS[finding]["verdict"]
        print(f"  Finding {finding:3d} ({truth:15s}): {stats['correct']:2d}/{stats['total']:2d} ({pct:5.1f}%)")

    # Average confidence
    print()
    print("Confidence Statistics:")
    print("-" * 80)
    confidences = [r['confidence'] for r in successful_tests if r['confidence'] is not None]
    if confidences:
        avg_conf = sum(confidences) / len(confidences)
        correct_confs = [r['confidence'] for r in correct_tests if r['confidence'] is not None]
        incorrect_confs = [r['confidence'] for r in successful_tests if not r.get('correct', False) and r['confidence'] is not None]

        print(f"  Overall avg confidence: {avg_conf:.1f}")
        if correct_confs:
            print(f"  Avg confidence (correct): {sum(correct_confs)/len(correct_confs):.1f}")
        if incorrect_confs:
            print(f"  Avg confidence (incorrect): {sum(incorrect_confs)/len(incorrect_confs):.1f}")

    print()
    print(f"Results saved to: {output_file}")
    print("=" * 120)

    # Return summary for integration
    summary = {
        "model": MODEL,
        "total_tests": len(results),
        "successful": len(successful_tests),
        "errors": len(failed_tests),
        "correct": len(correct_tests),
        "accuracy": round(accuracy, 3),
        "output_file": str(output_file),
        "timestamp": datetime.now().isoformat()
    }

    return summary


if __name__ == "__main__":
    summary = main()
    # Also print as JSON for easy parsing
    print()
    print("SUMMARY JSON:")
    print(json.dumps(summary, indent=2))
