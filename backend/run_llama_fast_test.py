#!/usr/bin/env python3
"""
Fast comprehensive test runner for llama3.3-70b-instruct model
Tests 1 model × 20 prompts × 13 findings = 260 tests
Optimized for speed with batch processing

Usage:
    python run_llama_fast_test.py
"""

import json
import requests
import sys
import re
import warnings
from typing import Dict, List
from datetime import datetime
from pathlib import Path

# Suppress SSL warnings
warnings.filterwarnings('ignore')

# Test findings (13 total: 3 original + 10 new)
TEST_FINDINGS = {
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

# Compact 20 prompts
PROMPTS = {
    "v1_code_first": "Code:\n```c\n{code}\n```\n\nClaim: {claim}\nVote (FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS):\nConfidence (0-100):\nReasoning:",
    "v2_verdict_first": "Claim: {claim}\n\nCode:\n```c\n{code}\n```\n\nVote:\nConfidence:\nReasoning:",
    "v3_numbered_steps": "1. CLAIM\n{claim}\n\n2. CODE\n```c\n{code}\n```\n\n3. ANALYSIS\nVote:\nConfidence:\nReasoning:",
    "v4_question_format": "Is this real?\nClaim: {claim}\nCode:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v5_checklist": "CLAIM: {claim}\nCODE:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v6_expert_persona": "UEFI expert review:\nClaim: {claim}\nCode:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v7_minimal": "Code:\n```c\n{code}\n```\nClaim: {claim}\nVote:\nConfidence:\nReasoning:",
    "v8_context_last": "Claim: {claim}\nCode:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v9_bullet_points": "• Claim: {claim}\n• Code:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v10_table_format": "Claim: {claim}\nCode:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v11_socratic": "Questions:\n1. Where is issue?\n2. Can attacker control it?\n3. Exploitable?\n\nClaim: {claim}\nCode:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v12_red_team": "Exploit test:\nClaim: {claim}\nCode:\n```c\n{code}\n```\nCan you exploit it?\nVote:\nConfidence:\nReasoning:",
    "v13_diff_format": "Scanner says: {claim}\nActual code:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v14_emoji_visual": "Alert: {claim}\nCode:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v15_json_structured": "JSON Analysis:\nClaim: {claim}\nCode:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v16_markdown_report": "# Report\nClaim: {claim}\nCode:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v17_xml_format": "<claim>{claim}</claim>\n<code>{code}</code>\nVote:\nConfidence:\nReasoning:",
    "v18_prose": "Review if real:\n{claim}\n\nCode:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v19_adversarial_skeptic": "Skeptical: assume wrong.\nClaim: {claim}\nCode:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
    "v20_chain_of_thought": "Step by step:\nClaim: {claim}\nCode:\n```c\n{code}\n```\nVote:\nConfidence:\nReasoning:",
}


def parse_vote(text: str) -> Dict:
    """Extract vote, confidence from response."""
    text_clean = re.sub(r'<think.*?</think>', '', text, flags=re.DOTALL)
    vote = None
    confidence = None

    lines = text_clean.lower().split('\n')
    for line in lines:
        if 'false positive' in line or 'false_positive' in line:
            vote = 'FALSE_POSITIVE'
        elif 'real' in line and 'vote' in line:
            vote = 'REAL'
        elif 'needs_verified' in line or 'needs verified' in line:
            vote = 'NEEDS_VERIFIED'
        elif 'weakness' in line and 'vote' in line:
            vote = 'WEAKNESS'

        if 'confidence' in line:
            nums = re.findall(r'\d+', line)
            if nums:
                try:
                    confidence = min(int(nums[0]), 100)
                except:
                    pass

    # Fallback keyword search
    if not vote:
        if 'false positive' in text_clean.lower():
            vote = 'FALSE_POSITIVE'
        elif re.search(r'\breal\b', text_clean.lower()):
            vote = 'REAL'
        elif 'needs_verified' in text_clean.lower():
            vote = 'NEEDS_VERIFIED'
        elif 'weakness' in text_clean.lower():
            vote = 'WEAKNESS'

    return {"vote": vote, "confidence": confidence}


def call_llm(prompt: str) -> str:
    """Call LLM synchronously."""
    try:
        resp = requests.post(
            "https://davy.labs.lenovo.com:5000/v1/chat/completions",
            json={
                "model": "llama3.3-70b-instruct",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 500
            },
            headers={"Authorization": "Bearer testkeyforchrisvp"},
            verify=False,
            timeout=120
        )
        return resp.json()['choices'][0]['message']['content']
    except Exception as e:
        raise Exception(f"API error: {e}")


def main():
    output_dir = Path("/tmp/comprehensive_results")
    output_dir.mkdir(parents=True, exist_ok=True)

    findings = sorted(TEST_FINDINGS.keys())
    prompts = list(PROMPTS.keys())
    total = len(findings) * len(prompts)

    print("=" * 100)
    print(f"LLAMA3.3-70B-INSTRUCT: 260 TESTS (13 findings × 20 prompts)")
    print("=" * 100)

    results = []
    test_num = 0

    for finding_id in findings:
        for prompt_name in prompts:
            test_num += 1
            finding = TEST_FINDINGS[finding_id]
            prompt_template = PROMPTS[prompt_name]
            prompt = prompt_template.format(
                code=finding["code"],
                claim=finding["claim"]
            )

            try:
                response = call_llm(prompt)
                parsed = parse_vote(response)
                correct = parsed['vote'] == finding["verdict"]

                result = {
                    "test_num": test_num,
                    "finding_id": finding_id,
                    "prompt": prompt_name,
                    "ground_truth": finding["verdict"],
                    "vote": parsed["vote"],
                    "confidence": parsed["confidence"],
                    "correct": correct
                }
                results.append(result)

                status = "OK" if correct else "XX"
                print(f"[{test_num:3d}/260] {status} F{finding_id:3d} {prompt_name:20s} => {parsed['vote'] or 'NONE':15s} ({parsed['confidence'] or 0:2})")

            except Exception as e:
                print(f"[{test_num:3d}/260] ER F{finding_id:3d} {prompt_name:20s} {str(e)[:40]}")
                results.append({
                    "test_num": test_num,
                    "finding_id": finding_id,
                    "prompt": prompt_name,
                    "error": str(e),
                    "ground_truth": finding["verdict"]
                })

    # Save results
    output_file = output_dir / "llama3.3-70b-instruct_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Stats
    successful = [r for r in results if 'error' not in r]
    correct = [r for r in successful if r.get('correct')]
    accuracy = len(correct) / len(successful) if successful else 0

    print()
    print("=" * 100)
    print(f"Total tests: {total}")
    print(f"Successful: {len(successful)}")
    print(f"Errors: {len(results) - len(successful)}")
    print(f"Correct: {len(correct)}")
    print(f"Accuracy: {100*accuracy:.1f}%")
    print(f"Output: {output_file}")
    print("=" * 100)

    # Prompt accuracy
    by_prompt = {}
    for r in successful:
        p = r['prompt']
        if p not in by_prompt:
            by_prompt[p] = [0, 0]
        by_prompt[p][1] += 1
        if r['correct']:
            by_prompt[p][0] += 1

    print("\nBy Prompt:")
    for p in sorted(by_prompt.keys()):
        c, t = by_prompt[p]
        print(f"  {p:20s}: {c:2d}/{t:2d} ({100*c/t:5.1f}%)")

    # Finding accuracy
    by_finding = {}
    for r in successful:
        f = r['finding_id']
        if f not in by_finding:
            by_finding[f] = [0, 0]
        by_finding[f][1] += 1
        if r['correct']:
            by_finding[f][0] += 1

    print("\nBy Finding:")
    for f in sorted(by_finding.keys()):
        c, t = by_finding[f]
        print(f"  Finding {f:3d}: {c:2d}/{t:2d} ({100*c/t:5.1f}%)")


if __name__ == "__main__":
    main()
