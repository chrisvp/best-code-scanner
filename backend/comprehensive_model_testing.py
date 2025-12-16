#!/usr/bin/env python3
"""
Comprehensive Multi-Model Prompt Testing Framework

Tests ALL available models with ALL prompt variations (20 total) on 13 test findings.

Test Matrix:
- Models: 5 (gpt-oss-120b, mistral-small, gemma-3-27b-it, llama3.3-70b-instruct, phi-4)
- Prompts: 20 (10 original + 10 new styles)
- Findings: 13 (3 original + 10 new from scan #13)
- Total: 5 × 20 × 13 = 1,300 tests

Uses parallel agent execution for efficiency.
"""

import json
import sqlite3
from pathlib import Path

# Test findings with ground truth
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

# Models to test (excluding kimi/embedding and reranker models)
MODELS = [
    "gpt-oss-120b",
    "mistral-small",
    "gemma-3-27b-it",
    "llama3.3-70b-instruct",
    "phi-4"
]

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

def create_test_plan():
    """Generate the comprehensive test plan."""
    plan = {
        "total_tests": len(MODELS) * len(PROMPTS) * len(TEST_FINDINGS),
        "models": MODELS,
        "prompts": list(PROMPTS.keys()),
        "findings": list(TEST_FINDINGS.keys()),
        "test_matrix": []
    }

    # Generate all combinations
    test_id = 0
    for model in MODELS:
        for prompt in PROMPTS.keys():
            for finding_id in TEST_FINDINGS.keys():
                plan["test_matrix"].append({
                    "test_id": test_id,
                    "model": model,
                    "prompt": prompt,
                    "finding_id": finding_id,
                    "ground_truth": TEST_FINDINGS[finding_id]["verdict"]
                })
                test_id += 1

    return plan

def save_test_plan(plan, filepath):
    """Save test plan to file."""
    with open(filepath, 'w') as f:
        json.dump(plan, f, indent=2)
    print(f"Test plan saved to: {filepath}")
    print(f"Total tests: {plan['total_tests']}")
    print(f"Models: {len(plan['models'])}")
    print(f"Prompts: {len(plan['prompts'])}")
    print(f"Findings: {len(plan['findings'])}")

if __name__ == "__main__":
    plan = create_test_plan()
    save_test_plan(plan, "/tmp/comprehensive_test_plan.json")

    # Save test findings for reference
    with open("/tmp/test_findings.json", 'w') as f:
        json.dump(TEST_FINDINGS, f, indent=2)
    print("\nTest findings saved to: /tmp/test_findings.json")

    # Save prompts for reference
    with open("/tmp/test_prompts.json", 'w') as f:
        json.dump(PROMPTS, f, indent=2)
    print("Test prompts saved to: /tmp/test_prompts.json")

    print("\n" + "="*80)
    print("TEST PLAN READY")
    print("="*80)
    print(f"Next: Run parallel agents to execute {plan['total_tests']} tests")
