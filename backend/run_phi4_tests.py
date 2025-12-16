#!/usr/bin/env python3
"""
Run 260 tests for phi-4 model (20 prompts × 13 findings)

Test Matrix:
- Model: phi-4
- Prompts: 20 (v1-v20)
- Findings: 13 (221, 213, 215, 211, 216, 218, 220, 223, 230, 232, 233, 234, 235)
- Total: 1 × 20 × 13 = 260 tests
"""

import json
import requests
import re
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
import time

# Ground truth for test cases
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
        "claim": "Size512 is 16-bit; multiplying by 512 can overflow 32-bit UINTN, causing ImageSize smaller than actual ROM size, resulting in buffer overflow.",
        "reasoning": "65,535 × 512 = 33,553,920 bytes (32 MB) < 4 GB. No overflow possible."
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
        "claim": "Code checks VarSize != 0 but doesn't verify VarSize >= sizeof(PBA_STATUS_VAR) before dereferencing.",
        "reasoning": "UEFI GetVariable returns whatever size was stored. Missing size check = OOB read."
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
        "claim": "Code assumes OsIndications is UINT64 but never verifies DataSize == sizeof(UINT64) before dereferencing.",
        "reasoning": "Missing DataSize validation = potential OOB read if variable is malformed."
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
        "claim": "Code assumes BootNext variable contains at least UINT16 and dereferences without size confirmation.",
        "reasoning": "Should verify variable size >= sizeof(UINT16) before dereference."
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
        "claim": "ImagePackage[j] may be NULL if OpenProtocol failed; code dereferences without null-check.",
        "reasoning": "Missing null check before array dereference = potential crash."
    },

    218: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/BootManager.c",
        "line": 192,
        "issue": "Uninitialized function pointer usage",
        "code": """return Item->mOldPciIoAttributes(This, Operation, Attributes, Result);""",
        "claim": "mOldPciIoAttributes only set when Pci->Attributes != PciIoAttributesFilter; otherwise remains uninitialized.",
        "reasoning": "Invoking uninitialized function pointer = undefined behavior."
    },

    220: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/Legacy.c",
        "line": 1366,
        "issue": "OOB write to IdeDiskInfo array",
        "code": """IbvBbs->IdeDiskInfo[IdeInfo].DiskInfoDeviceType = BBS_IDE_HDD_DEVICE_TYPE;""",
        "claim": "IdeInfo incremented without bounds check against IdeDiskInfo array size.",
        "reasoning": "Unbounded array index = potential buffer overflow."
    },

    223: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/Legacy.c",
        "line": 1665,
        "issue": "OOB access of HddInfo array",
        "code": """if (((HddInfo[HddInfoIndex].Status & HDD_PRIMARY) != 0) ...) { ... }""",
        "claim": "HddInfoIndex derived from BbsOrder without bounds checking.",
        "reasoning": "Attacker-controlled index = OOB read/write."
    },

    230: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/Legacy.c",
        "line": 4193,
        "issue": "NULL pointer dereference when querying SMI",
        "code": """Status = SwSmiAllocator->QuerySwSmi(&mCsmSwSmiGuidArray[SCT_CSM_LEGACY_USB_BY_IRQ], &CsmSwSmiInputValue);""",
        "claim": "SwSmiAllocator may be NULL if protocol lookup fails.",
        "reasoning": "Missing null check before pointer dereference = crash."
    },

    232: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/Legacy.c",
        "line": 5338,
        "issue": "OOB write to BbsTable arrays",
        "code": """BbsTableDevicePaths[i] = DuplicateDevicePath(DevicePath);
BbsTable[i].BootPriority = BBS_UNPRIORITIZED_ENTRY;""",
        "claim": "Index i derived from device ranges but equals BbsCount, allowing writes past allocated tables.",
        "reasoning": "Index >= array size = buffer overflow."
    },

    233: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/Legacy.c",
        "line": 5486,
        "issue": "OOB access via unchecked buffer index",
        "code": """if (BbsTableDevicePaths[Buffer[Index]] != NULL) { ... }""",
        "claim": "Buffer[Index] used as array index without bounds verification.",
        "reasoning": "Unchecked array indexing = OOB read."
    },

    234: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/BootManager.c",
        "line": 5939,
        "issue": "Integer overflow in OptionalDataLength calculation",
        "code": """*OptionalDataLength += (UINT32)GetDevicePathSize(*DevicePath);""",
        "claim": "GetDevicePathSize() can return large value; adding without overflow check may wrap size.",
        "reasoning": "Integer overflow → undersized allocation → heap buffer overflow."
    },

    235: {
        "verdict": "REAL",
        "file_path": "BootManagerDxe/BootManager.c",
        "line": 1049,
        "issue": "Integer overflow / infinite loop in boot-option lookup",
        "code": """for (j = 0; j < (mProtectedBootOptionsSize / sizeof(UINT16)); j++) { ... }""",
        "claim": "Loop counter j is UINT16; if size exceeds 0xFFFF × 2 bytes, comparison wraps and loop never terminates.",
        "reasoning": "Loop counter overflow = infinite loop DoS."
    },
}

# 20 prompt variations
PROMPTS = {
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

def call_llm(model: str, prompt: str, base_url: str = "https://davy.labs.lenovo.com:5000/v1", retries: int = 3) -> Optional[Dict]:
    """Call LLM via OpenAI-compatible API with retries."""
    for attempt in range(retries):
        try:
            response = requests.post(
                f"{base_url}/chat/completions",
                json={
                    "model": model,
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
        except requests.exceptions.Timeout:
            print(f"  Timeout on attempt {attempt+1}/{retries}, retrying...")
            if attempt < retries - 1:
                time.sleep(2)
            continue
        except Exception as e:
            print(f"  Error on attempt {attempt+1}/{retries}: {e}")
            if attempt < retries - 1:
                time.sleep(2)
            continue
    return None

def test_finding(finding_id: int, prompt_variant: str, base_url: str) -> Dict:
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
        response = call_llm("phi-4", prompt, base_url)

        if response is None:
            return {
                "finding_id": finding_id,
                "prompt_variant": prompt_variant,
                "error": "LLM call failed after retries",
                "timestamp": datetime.now().isoformat()
            }

        response_text = response['choices'][0]['message']['content']
        parsed = parse_vote(response_text)

        correct = parsed['vote'] == truth['verdict']

        result = {
            "finding_id": finding_id,
            "prompt_variant": prompt_variant,
            "ground_truth": truth["verdict"],
            "model_vote": parsed["vote"],
            "confidence": parsed["confidence"],
            "correct": correct,
            "reasoning": parsed["reasoning"][:500],  # Truncate for space
            "timestamp": datetime.now().isoformat()
        }

        return result

    except Exception as e:
        return {
            "finding_id": finding_id,
            "prompt_variant": prompt_variant,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def main():
    """Run all 260 tests for phi-4."""
    base_url = "https://davy.labs.lenovo.com:5000/v1"
    output_dir = Path("/tmp/comprehensive_results")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "phi-4_results.json"

    finding_ids = sorted(TEST_FINDINGS.keys())
    prompt_variants = list(PROMPTS.keys())

    total_tests = len(finding_ids) * len(prompt_variants)

    print("\n" + "="*80)
    print("PHI-4 COMPREHENSIVE TEST SUITE")
    print("="*80)
    print(f"Model: phi-4")
    print(f"Findings: {len(finding_ids)}")
    print(f"Prompts: {len(prompt_variants)}")
    print(f"Total tests: {total_tests}")
    print(f"Output: {output_file}")
    print("="*80 + "\n")

    results = []
    test_num = 0

    for finding_id in finding_ids:
        print(f"\nFinding {finding_id} ({TEST_FINDINGS[finding_id]['issue']}):")

        for prompt_variant in prompt_variants:
            test_num += 1
            print(f"  [{test_num:3d}/{total_tests}] Testing with {prompt_variant}...", end=" ", flush=True)

            result = test_finding(finding_id, prompt_variant, base_url)
            results.append(result)

            if "error" in result:
                print(f"ERROR: {result['error']}")
            else:
                status = "✓" if result["correct"] else "✗"
                print(f"{status} {result['model_vote']} (confidence: {result['confidence']})")

            # Small delay to avoid hammering the server
            time.sleep(0.1)

    # Save results
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n\nResults saved to: {output_file}")

    # Calculate statistics
    print("\n" + "="*80)
    print("SUMMARY STATISTICS")
    print("="*80)

    successful_results = [r for r in results if "error" not in r]
    failed_results = [r for r in results if "error" in r]

    print(f"\nTotal tests: {len(results)}")
    print(f"Successful: {len(successful_results)}")
    print(f"Failed: {len(failed_results)}")

    if successful_results:
        correct_count = sum(1 for r in successful_results if r.get("correct"))
        accuracy = 100 * correct_count / len(successful_results)
        print(f"\nOverall Accuracy: {correct_count}/{len(successful_results)} ({accuracy:.1f}%)")

        # Accuracy by finding
        print("\nAccuracy by Finding:")
        accuracy_by_finding = {}
        for result in successful_results:
            finding_id = result['finding_id']
            if finding_id not in accuracy_by_finding:
                accuracy_by_finding[finding_id] = {"correct": 0, "total": 0}
            accuracy_by_finding[finding_id]["total"] += 1
            if result["correct"]:
                accuracy_by_finding[finding_id]["correct"] += 1

        for finding_id in sorted(accuracy_by_finding.keys()):
            stats = accuracy_by_finding[finding_id]
            pct = 100 * stats["correct"] / stats["total"]
            issue = TEST_FINDINGS[finding_id]["issue"]
            print(f"  Finding {finding_id} ({issue[:40]}...): {stats['correct']}/{stats['total']} ({pct:.1f}%)")

        # Accuracy by prompt
        print("\nAccuracy by Prompt Variant:")
        accuracy_by_prompt = {}
        for result in successful_results:
            prompt = result['prompt_variant']
            if prompt not in accuracy_by_prompt:
                accuracy_by_prompt[prompt] = {"correct": 0, "total": 0}
            accuracy_by_prompt[prompt]["total"] += 1
            if result["correct"]:
                accuracy_by_prompt[prompt]["correct"] += 1

        for prompt in sorted(accuracy_by_prompt.keys(),
                            key=lambda x: accuracy_by_prompt[x]["correct"] / accuracy_by_prompt[x]["total"],
                            reverse=True):
            stats = accuracy_by_prompt[prompt]
            pct = 100 * stats["correct"] / stats["total"]
            print(f"  {prompt}: {stats['correct']}/{stats['total']} ({pct:.1f}%)")

        # Confidence stats
        confidences = [r['confidence'] for r in successful_results if r['confidence'] is not None]
        if confidences:
            avg_confidence = sum(confidences) / len(confidences)
            print(f"\nAverage Confidence: {avg_confidence:.1f}%")
            print(f"Confidence Range: {min(confidences)} - {max(confidences)}")

    print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    main()
