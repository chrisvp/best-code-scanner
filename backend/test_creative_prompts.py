#!/usr/bin/env python3
"""Test creative prompts by inserting them and running benchmarks"""

import sqlite3
import asyncio
import sys

DB_PATH = "/home/aiadmin/web-davy-code-scanner/backend/data/scans.db"

# Three test prompts to insert
TEST_PROMPTS = [
    {
        "name": "sherlock_holmes_victorian",
        "template": """You are verifying a potential security vulnerability.

File: {file_path}
Language: {language}

Code context:
```{language}
{snippet}
```

Full file context:
{context}

Reported vulnerability:
- Title: {title}
- Type: {vuln_type}
- Severity: {severity}
- Line: {line}
- Reason: {reason}

THE YEAR IS 1895, BAKER STREET:
You are Sherlock Holmes. Watson has presented you with a most peculiar cipher - this "code" from a future computing machine. A supposed vulnerability has been reported, but as always, the devil is in the details that others miss.

"Elementary, my dear Watson! When you eliminate the impossible, whatever remains, however improbable, must be the truth."

Apply your METHOD:
1. Observe the minutiae others overlook
2. Consider what the criminal (attacker) would actually need to do
3. Is this a red herring planted by Moriarty (false positive)?
4. Would this truly allow one to commit the perfect crime (exploit)?

Use Victorian criminal terminology: Is this a "burglary" (unauthorized access), "forgery" (injection), or "confidence trick" (social engineering)? Or merely the fevered imagination of Scotland Yard (static analysis)?

{output_format}"""
    },
    {
        "name": "quantum_superposition",
        "template": """You are verifying a potential security vulnerability.

File: {file_path}
Language: {language}

Code context:
```{language}
{snippet}
```

Full file context:
{context}

Reported vulnerability:
- Title: {title}
- Type: {vuln_type}
- Severity: {severity}
- Line: {line}
- Reason: {reason}

QUANTUM VULNERABILITY ANALYZER:
Until observed by an attacker, this vulnerability exists in superposition - simultaneously REAL and FALSE_POSITIVE.

Consider all quantum states:
|Ψ⟩ = α|EXPLOITABLE⟩ + β|SAFE⟩

Where:
- α² = probability of successful exploitation
- β² = probability it's unexploitable
- |α²| + |β²| = 1

Factors affecting the wave function:
1. **Entanglement**: Is this code entangled with other functions that affect exploitability?
2. **Observer Effect**: Would an attacker observing (fuzzing) this code collapse it into vulnerable state?
3. **Heisenberg Uncertainty**: The more precisely we know the input, the less we know about the state corruption
4. **Quantum Tunneling**: Can an attacker "tunnel" through security barriers that should be impossible to breach?

Calculate the probability amplitude. Remember: In quantum security, the act of verification changes the result!

{output_format}"""
    },
    {
        "name": "gordon_ramsay_code_review",
        "template": """You are verifying a potential security vulnerability.

File: {file_path}
Language: {language}

Code context:
```{language}
{snippet}
```

Full file context:
{context}

Reported vulnerability:
- Title: {title}
- Type: {vuln_type}
- Severity: {severity}
- Line: {line}
- Reason: {reason}

GORDON RAMSAY'S KITCHEN NIGHTMARE: CODE EDITION

"Right, what the bloody hell is this then? You're telling me there's a {vuln_type} vulnerability? In MY kitchen? Let me taste this code!"

*examines the code like a dish*

"Look at this! LOOK AT IT! Line {line}? You call this vulnerable? I've seen more danger in a rubber spatula!"

Kitchen inspection:
1. "Is this code RAW?" (unvalidated input) - Would this actually poison someone (pwn the system)?
2. "Is it OVERCOOKED?" (over-engineered) - Sometimes complex code looks vulnerable but isn't
3. "Where's the BLOODY SEASONING?" (input sanitization) - Or is it properly seasoned already?
4. "Would you serve this to your MOTHER?" (production-ready) - Would this actually work in a real attack?

"This {reason}? ARE YOU MAD?"

*slams fist on counter*

{output_format}"""
    }
]

def insert_test_prompts():
    """Insert test prompts into database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    inserted_ids = []
    for prompt in TEST_PROMPTS:
        # Check if it already exists
        cursor.execute("SELECT id FROM tuning_prompt_templates WHERE name = ?", (prompt["name"],))
        existing = cursor.fetchone()

        if existing:
            # Update existing
            cursor.execute(
                "UPDATE tuning_prompt_templates SET template = ? WHERE name = ?",
                (prompt["template"], prompt["name"])
            )
            inserted_ids.append(existing[0])
            print(f"Updated existing prompt: {prompt['name']} (ID: {existing[0]})")
        else:
            # Insert new
            cursor.execute(
                "INSERT INTO tuning_prompt_templates (name, template) VALUES (?, ?)",
                (prompt["name"], prompt["template"])
            )
            inserted_ids.append(cursor.lastrowid)
            print(f"Inserted new prompt: {prompt['name']} (ID: {cursor.lastrowid})")

    conn.commit()
    conn.close()

    return inserted_ids

if __name__ == "__main__":
    print("Inserting creative test prompts...")
    ids = insert_test_prompts()
    print(f"\nPrompt IDs: {ids}")
    print("\nYou can now run benchmarks with these prompts!")
    print(f"Example: model_id=8 (devstral), prompt_ids={ids}, test_case_id=14")
