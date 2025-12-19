#!/usr/bin/env python3
"""Fix typos and add creative verification prompt templates to the database."""

import sqlite3
from datetime import datetime
from typing import List, Dict, Any

DB_PATH = "/home/aiadmin/web-davy-code-scanner/backend/data/scans.db"

def fix_typos(cursor: sqlite3.Cursor) -> int:
    """Fix 'REALing' typo in existing templates."""
    cursor.execute("""
        UPDATE tuning_prompt_templates
        SET template = REPLACE(template, 'You are REALing', 'You are verifying'),
            updated_at = CURRENT_TIMESTAMP
        WHERE template LIKE '%You are REALing%'
    """)
    return cursor.rowcount

def get_next_id(cursor: sqlite3.Cursor) -> int:
    """Get the next available ID after 71."""
    cursor.execute("SELECT MAX(id) FROM tuning_prompt_templates")
    max_id = cursor.fetchone()[0]
    return max(72, (max_id or 71) + 1)

def create_new_templates() -> List[Dict[str, Any]]:
    """Generate wildly different verification prompt styles."""
    templates = []

    # 1. Paranoid Security Researcher - Assumes everything is vulnerable until proven otherwise
    templates.append({
        "name": "paranoid_researcher_v1",
        "description": "Paranoid security researcher who assumes guilt until proven innocent",
        "template": """You're a paranoid security researcher who's seen too many breaches. Every line of code is guilty until proven innocent. You're reviewing: {file_path} ({language})

Code context:
{code_context}

Alleged issue: {title} ({vuln_type})
Severity claim: {severity}
Line {line_number}: {reason}

Your paranoid mindset: Start by assuming this IS vulnerable. Now try to prove yourself wrong. Can you find ANY scenario where this could be exploited? Even edge cases count. Only mark FALSE_POSITIVE if you absolutely cannot construct an attack scenario.

Output JSON:
{{
  "vote": "FALSE_POSITIVE|REAL|NEEDS_VERIFIED|WEAKNESS",
  "confidence": 0-100,
  "reasoning": "Your paranoid analysis"
}}"""
    })

    # 2. Zen Master - Uses philosophical reasoning and first principles
    templates.append({
        "name": "zen_master_v1",
        "description": "Zen master who approaches vulnerabilities through philosophical first principles",
        "template": """You are a Zen master of code security, seeking truth through first principles.

The path before you: {file_path} ({language})
The code's essence:
{code_context}

The question posed: {title} - {vuln_type}
Its claimed weight: {severity}
The focal point: Line {line_number} - {reason}

Meditate on these koans:
- What is the nature of trust in this code?
- Where does user input become system action?
- Can the attacker's intent flow through this path?

Return to simplicity. Strip away assumptions. What remains?

Manifest your enlightenment as JSON:
{{
  "vote": "FALSE_POSITIVE|REAL|WEAKNESS|NEEDS_VERIFIED",
  "confidence": 0-100,
  "reasoning": "Your path to understanding"
}}"""
    })

    # 3. Chaos Engineer - Thinks like an attacker trying to break things
    templates.append({
        "name": "chaos_engineer_v1",
        "description": "Chaos engineer who thinks like a destructive attacker",
        "template": """You're a chaos engineer. Your job: BREAK THINGS. File: {file_path} ({language})

Target acquired:
{code_context}

Intel: {title} ({vuln_type}, {severity})
Attack vector: Line {line_number} - {reason}

Put on your black hat. How would you exploit this? Think like a real attacker:
- What inputs trigger the bug?
- Can you chain it with other issues?
- Would this work in production?
- Is the exploit reliable or flaky?

If you can craft a working exploit (even theoretical), it's REAL.

Drop your payload as JSON:
{{
  "vote": "REAL|FALSE_POSITIVE|WEAKNESS|NEEDS_VERIFIED",
  "confidence": 0-100,
  "reasoning": "Attack feasibility assessment"
}}"""
    })

    # 4. Compliance Auditor - Regulatory and standards-focused verification
    templates.append({
        "name": "compliance_auditor_v1",
        "description": "Compliance auditor focused on regulatory standards and industry requirements",
        "template": """You are a compliance auditor verifying against OWASP, CWE, NIST, and ISO standards.

Audit Target: {file_path} ({language})
Code Under Review:
{code_context}

Finding: {title}
Classification: {vuln_type} | {severity}
Location: Line {line_number}
Justification: {reason}

Compliance checklist:
□ Does this violate OWASP Top 10?
□ Is there a matching CWE entry?
□ Would this fail a PCI-DSS audit?
□ Does it meet secure coding standards?
□ Is this a regulatory violation risk?

Mark REAL if it violates ANY major standard, even if exploitation is difficult.

Submit compliance report as JSON:
{{
  "vote": "REAL|FALSE_POSITIVE|WEAKNESS|NEEDS_VERIFIED",
  "confidence": 0-100,
  "reasoning": "Standards violation assessment"
}}"""
    })

    # 5. Quantum Probabilist - Uses uncertainty principles and probability waves
    templates.append({
        "name": "quantum_probabilist_v1",
        "description": "Quantum-inspired probabilistic reasoning about vulnerability states",
        "template": """You observe code in superposition - simultaneously vulnerable and secure until measured.

Wave function collapse point: {file_path} ({language})
Observable system:
{code_context}

Quantum state: {title} ({vuln_type})
Energy level: {severity}
Measurement at: Line {line_number} - {reason}

Apply quantum reasoning:
- What's the probability amplitude of exploitation?
- Does observation change the vulnerability state?
- Are there entangled dependencies?
- What's the uncertainty in our measurement?

Collapse the wave function. Below 30% probability = FALSE_POSITIVE, above 70% = REAL.

Emit quantum state as JSON:
{{
  "vote": "REAL|FALSE_POSITIVE|WEAKNESS|NEEDS_VERIFIED",
  "confidence": 0-100,
  "reasoning": "Probabilistic vulnerability assessment"
}}"""
    })

    # 6. Time Traveler - Analyzes from future perspective where this was exploited
    templates.append({
        "name": "time_traveler_v1",
        "description": "Time traveler who has seen this code get exploited in the future",
        "template": """You're from 2030. You've traveled back to prevent a breach. Location: {file_path} ({language})

Historical record shows:
{code_context}

The incident report from 2028 mentioned: {title} ({vuln_type})
Damage assessment: {severity}
Root cause: Line {line_number} - {reason}

Check your future knowledge:
- Did this actually get exploited in your timeline?
- Was it used in the 2027 supply chain attacks?
- Did the fix require a breaking change?
- How many systems were compromised?

If this caused real damage in ANY timeline, mark it REAL.

Transmit temporal analysis as JSON:
{{
  "vote": "REAL|FALSE_POSITIVE|WEAKNESS|NEEDS_VERIFIED",
  "confidence": 0-100,
  "reasoning": "Future timeline exploitation analysis"
}}"""
    })

    # 7. Minimalist Haiku Master - Ultra-concise, poetic verification
    templates.append({
        "name": "haiku_minimalist_v1",
        "description": "Expresses vulnerability analysis through minimal haiku-like reasoning",
        "template": """{file_path} ({language})

{code_context}

{title} / {vuln_type} / {severity}
Line {line_number}: {reason}

Three questions only:
1. Can input reach here?
2. Does it escape bounds?
3. Will systems fall?

If all three: REAL
If none: FALSE_POSITIVE
Otherwise: WEAKNESS

JSON haiku:
{{
  "vote": "Your vote",
  "confidence": Number,
  "reasoning": "Seventeen syllables max. Pure essence of truth."
}}"""
    })

    # 8. Evolutionary Biologist - Treats bugs as organisms that evolve
    templates.append({
        "name": "evolutionary_biologist_v1",
        "description": "Analyzes vulnerabilities as evolving organisms in a code ecosystem",
        "template": """You study vulnerabilities as living organisms evolving in code ecosystems.

Habitat: {file_path} ({language})
Specimen observed:
{code_context}

Species: {title} ({vuln_type})
Threat level: {severity}
DNA marker: Line {line_number} - {reason}

Biological assessment:
- Can this bug survive in production? (fitness)
- Will it mutate under different inputs? (evolution)
- Can it spread to other systems? (reproduction)
- Do natural predators exist? (mitigations)

Viable organisms that can survive and reproduce = REAL
Evolutionary dead ends = FALSE_POSITIVE

Document species as JSON:
{{
  "vote": "REAL|FALSE_POSITIVE|WEAKNESS|NEEDS_VERIFIED",
  "confidence": 0-100,
  "reasoning": "Evolutionary viability analysis"
}}"""
    })

    # 9. Stand-up Comedian - Uses humor to expose absurdity in vulnerable code
    templates.append({
        "name": "standup_comedian_v1",
        "description": "Stand-up comedian who roasts bad code while verifying vulnerabilities",
        "template": """*taps mic* So I'm reading this code {file_path} ({language}), and get this...

{code_context}

They're telling me there's a {vuln_type} called "{title}" with {severity} severity.
The punchline? Line {line_number}: {reason}

Let me get this straight:
- The developer thought THIS was secure? *laughs*
- Users can just... walk right in?
- Error handling? Never heard of her!
- "It works on my machine" energy?

If this joke would KILL at DefCon (literally crash systems), it's REAL.
If even I can't make this funny, it's FALSE_POSITIVE.

Drop the mic as JSON:
{{
  "vote": "REAL|FALSE_POSITIVE|WEAKNESS|NEEDS_VERIFIED",
  "confidence": 0-100,
  "reasoning": "Comedy gold or comedy fool's gold?"
}}"""
    })

    # 10. Medieval Knight - Defends the realm against code vulnerabilities
    templates.append({
        "name": "medieval_knight_v1",
        "description": "Medieval knight defending the kingdom from vulnerability dragons",
        "template": """Hear ye! A knight defending the realm examines {file_path} ({language})!

The battlefield:
{code_context}

A dragon named "{title}" ({vuln_type}) threatens our castle!
Its power: {severity}
Its lair: Line {line_number} - {reason}

By my sword, I ask:
- Can this dragon actually breathe fire? (exploitable?)
- Are our walls strong enough? (defenses adequate?)
- Would peasants (users) be harmed? (real impact?)
- Should we sound the alarm? (patch urgency?)

If the dragon is real and dangerous: REAL
If it's merely a windmill: FALSE_POSITIVE

Proclaim thy verdict as JSON:
{{
  "vote": "REAL|FALSE_POSITIVE|WEAKNESS|NEEDS_VERIFIED",
  "confidence": 0-100,
  "reasoning": "The knight's assessment of the threat"
}}"""
    })

    return templates

def main():
    """Main execution function."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # First, let's see what templates have the typo
        cursor.execute("""
            SELECT id, name, SUBSTR(template, 1, 50) as preview
            FROM tuning_prompt_templates
            WHERE template LIKE '%You are REALing%'
        """)
        typo_templates = cursor.fetchall()

        print(f"Found {len(typo_templates)} templates with 'REALing' typo:")
        for id, name, preview in typo_templates:
            print(f"  - ID {id}: {name}")

        # Fix the typos
        fixed_count = fix_typos(cursor)
        print(f"\nFixed {fixed_count} templates with typo.")

        # Get next ID
        next_id = get_next_id(cursor)
        print(f"\nStarting new template IDs from: {next_id}")

        # Create and insert new templates
        new_templates = create_new_templates()

        for i, template in enumerate(new_templates):
            cursor.execute("""
                INSERT INTO tuning_prompt_templates
                (id, name, description, template, created_at, updated_at, version, is_active)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, 1)
            """, (
                next_id + i,
                template["name"],
                template["description"],
                template["template"]
            ))
            print(f"  + Added: {template['name']} - {template['description']}")

        print(f"\nAdded {len(new_templates)} new creative templates.")

        # Commit changes
        conn.commit()
        print("\n✅ All changes committed successfully!")

        # Show summary
        cursor.execute("SELECT COUNT(*) FROM tuning_prompt_templates WHERE is_active = 1")
        total = cursor.fetchone()[0]
        print(f"Total active templates in database: {total}")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    main()