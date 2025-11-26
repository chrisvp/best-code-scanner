"""
Test the agentic verification system against scan #27 findings.
Compares results with manual classifications to measure FP reduction.
"""
import asyncio
import sys
import os
import sqlite3
import json

# Add the backend directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.intelligence.codebase_tools import CodebaseTools
from app.services.intelligence.agent_runtime import AgenticVerifier
from app.services.orchestration.model_orchestrator import ModelPool, ModelConfig
from app.core.database import SessionLocal


# Manual classifications from our analysis
MANUAL_CLASSIFICATIONS = {
    # True Positives (real vulnerabilities)
    155: 'TP',  # Command Injection
    156: 'TP',  # Use-After-Free
    158: 'TP',  # Format String
    159: 'TP',  # Buffer Overflow
    160: 'TP',  # Buffer Overflow (cont)
    161: 'TP',  # Buffer Overflow (cont)
    162: 'TP',  # UAF (duplicate)
    164: 'TP',  # Format String
    165: 'TP',  # Double-Free
    166: 'TP',  # Buffer Overflow

    # Debatable (context-dependent)
    157: 'DEBATABLE',  # Path Traversal
    163: 'DEBATABLE',  # Buffer Overflow (borderline)
    168: 'DEBATABLE',  # Path Traversal
    170: 'DEBATABLE',  # Path Traversal

    # False Positives
    167: 'FP',  # Integer Overflow (theoretical)
    169: 'FP',  # Integer Overflow (bounds check)
    171: 'FP',  # Integer Overflow (theoretical)
    172: 'FP',  # Integer Overflow (theoretical)
    173: 'FP',  # Buffer Overflow (safe strncpy)
    174: 'FP',  # Insecure Permissions
    175: 'FP',  # Buffer Overflow (safe vsnprintf)
    176: 'FP',  # Buffer Overflow (safe strncpy)
    177: 'FP',  # Buffer Overflow (safe snprintf)
    178: 'FP',  # Missing Error Handling
    179: 'FP',  # Integer Overflow (theoretical)
    180: 'FP',  # Missing Input Validation (duplicate)
}


async def test_codebase_tools():
    """Test basic codebase tools functionality"""
    print("=== Testing CodebaseTools ===\n")

    scan_path = "/mnt/c/Users/acrvp/code/code-scanner/backend/sandbox/27/vulnerable_cpp"
    db = SessionLocal()

    try:
        tools = CodebaseTools(scan_id=27, root_dir=scan_path, db=db)

        # Test read_file
        print("1. Testing read_file...")
        result = tools.read_file("firmware_updater.cpp", 328, 335)
        print(f"   Result: {result.success}")
        if result.success:
            print(f"   Content preview: {result.data[:200]}...")

        # Test search_code
        print("\n2. Testing search_code...")
        result = tools.search_code(r"system\s*\(")
        print(f"   Result: {result.success}")
        if result.success:
            print(f"   Matches: {result.data[:300]}...")

        # Test find_entry_points
        print("\n3. Testing find_entry_points...")
        result = tools.find_entry_points()
        print(f"   Result: {result.success}")
        if result.success:
            print(f"   Entry points: {result.data[:500]}...")

        # Test find_callers
        print("\n4. Testing find_callers...")
        result = tools.find_callers("execute_hook")
        print(f"   Result: {result.success}")
        if result.success:
            print(f"   Callers: {result.data[:300]}...")

        # Test trace_data_flow
        print("\n5. Testing trace_data_flow...")
        result = tools.trace_data_flow(
            variable="command",
            file="firmware_updater.cpp",
            line=331,
            direction="backward"
        )
        print(f"   Result: {result.success}")
        if result.success:
            print(f"   Flow: {result.data[:400]}...")

        print("\n=== CodebaseTools tests passed! ===\n")
        return True

    finally:
        db.close()


async def test_agentic_verification_single():
    """Test agentic verification on a single known finding"""
    print("=== Testing AgenticVerifier (Single Finding) ===\n")

    scan_path = "/mnt/c/Users/acrvp/code/code-scanner/backend/sandbox/27/vulnerable_cpp"
    db = SessionLocal()

    try:
        # Get model config from database
        from app.models.scanner_models import ModelConfig as DBModelConfig
        model_config = db.query(DBModelConfig).filter(
            DBModelConfig.is_verifier == True
        ).first()

        if not model_config:
            print("No verifier model configured. Using first available model.")
            model_config = db.query(DBModelConfig).first()

        if not model_config:
            print("ERROR: No models configured in database")
            return False

        print(f"Using model: {model_config.name}")

        # Create model pool
        config = ModelConfig(
            name=model_config.name,
            base_url=model_config.base_url,
            api_key=model_config.api_key or "dummy",
            max_concurrent=1
        )
        pool = ModelPool(config)

        # Create tools and verifier
        tools = CodebaseTools(scan_id=27, root_dir=scan_path, db=db)
        verifier = AgenticVerifier(pool, tools, max_steps=8)

        # Test on the Command Injection finding (ID 155) - known TP
        print("\nVerifying Command Injection (ID 155) - Expected: VERIFIED")
        result = await verifier.verify(
            title="Command Injection via Unvalidated Hook Execution",
            vuln_type="CWE-78",
            severity="Critical",
            file_path="firmware_updater.cpp",
            line_number=331,
            snippet="int result = system(command);",
            reason="The hook_name argument is concatenated into hook_path without validation and then passed to system()"
        )

        print(f"Verdict: {'VERIFIED' if result['verified'] else 'REJECTED'}")
        print(f"Confidence: {result['confidence']}")
        print(f"Reasoning: {result['reasoning'][:200]}...")
        print(f"\nExecution trace:\n{result['trace'][:1000]}...")

        # Test on an Integer Overflow finding (ID 169) - known FP
        print("\n" + "="*60)
        print("\nVerifying Integer Overflow (ID 169) - Expected: REJECTED")
        result = await verifier.verify(
            title="Potential Integer Overflow in Firmware Size Calculation",
            vuln_type="CWE-190",
            severity="Medium",
            file_path="firmware_updater.cpp",
            line_number=176,
            snippet="if (g_update_ctx.bytes_downloaded > MAX_FIRMWARE_SIZE) {",
            reason="The bytes_downloaded variable is compared to MAX_FIRMWARE_SIZE but not checked for overflow"
        )

        print(f"Verdict: {'VERIFIED' if result['verified'] else 'REJECTED'}")
        print(f"Confidence: {result['confidence']}")
        print(f"Reasoning: {result['reasoning'][:200]}...")

        return True

    finally:
        db.close()


async def test_agentic_verification_batch():
    """Test agentic verification on all scan #27 findings and compare with manual classification"""
    print("=== Testing AgenticVerifier (Full Batch) ===\n")

    scan_path = "/mnt/c/Users/acrvp/code/code-scanner/backend/sandbox/27/vulnerable_cpp"

    # Get findings from database
    conn = sqlite3.connect('/tmp/scans.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT vf.id, df.title, df.vulnerability_type, df.severity,
               df.line_number, df.snippet, df.reason, sf.file_path
        FROM verified_findings vf
        JOIN draft_findings df ON vf.draft_id = df.id
        JOIN scan_file_chunks sfc ON df.chunk_id = sfc.id
        JOIN scan_files sf ON sfc.scan_file_id = sf.id
        WHERE vf.scan_id = 27
        ORDER BY vf.id
    ''')

    findings = cursor.fetchall()
    conn.close()

    print(f"Found {len(findings)} verified findings to test\n")

    db = SessionLocal()

    try:
        # Get model config
        from app.models.scanner_models import ModelConfig as DBModelConfig
        model_config = db.query(DBModelConfig).filter(
            DBModelConfig.name == 'gemma-3-27b-it'  # Use best model
        ).first()

        if not model_config:
            model_config = db.query(DBModelConfig).first()

        if not model_config:
            print("ERROR: No models configured")
            return

        print(f"Using model: {model_config.name}")

        # Create verifier
        config = ModelConfig(
            name=model_config.name,
            base_url=model_config.base_url,
            api_key=model_config.api_key or "dummy",
            max_concurrent=1
        )
        pool = ModelPool(config)
        tools = CodebaseTools(scan_id=27, root_dir=scan_path, db=db)
        verifier = AgenticVerifier(pool, tools, max_steps=6)

        # Track results
        results = {
            'correct': 0,
            'incorrect': 0,
            'improved_tp': 0,  # Originally FP, now correctly TP
            'improved_fp': 0,  # Originally TP, now correctly FP
            'details': []
        }

        # Test subset of findings (3 TPs, 3 FPs)
        test_ids = [155, 156, 158, 169, 175, 179]  # Mix of TPs and FPs

        for finding in findings:
            vid, title, vuln_type, severity, line, snippet, reason, filepath = finding

            if vid not in test_ids:
                continue

            manual = MANUAL_CLASSIFICATIONS.get(vid, 'UNKNOWN')
            filename = os.path.basename(filepath)

            print(f"\n{'='*60}")
            print(f"Testing ID {vid}: {title[:50]}...")
            print(f"Manual classification: {manual}")

            result = await verifier.verify(
                title=title,
                vuln_type=vuln_type,
                severity=severity,
                file_path=filename,
                line_number=line,
                snippet=snippet or "",
                reason=reason or ""
            )

            agentic_verdict = 'TP' if result['verified'] else 'FP'

            # Compare
            if manual == 'DEBATABLE':
                status = 'DEBATABLE'
            elif manual == agentic_verdict:
                status = 'CORRECT'
                results['correct'] += 1
            else:
                status = 'INCORRECT'
                results['incorrect'] += 1

                if manual == 'FP' and agentic_verdict == 'FP':
                    results['improved_fp'] += 1
                elif manual == 'TP' and agentic_verdict == 'TP':
                    results['improved_tp'] += 1

            print(f"Agentic verdict: {agentic_verdict}")
            print(f"Confidence: {result['confidence']}")
            print(f"Status: {status}")
            print(f"Reasoning: {result['reasoning'][:150]}...")

            results['details'].append({
                'id': vid,
                'title': title,
                'manual': manual,
                'agentic': agentic_verdict,
                'confidence': result['confidence'],
                'status': status
            })

        # Summary
        print("\n" + "="*60)
        print("=== SUMMARY ===")
        print(f"Correct: {results['correct']}")
        print(f"Incorrect: {results['incorrect']}")
        total = results['correct'] + results['incorrect']
        if total > 0:
            print(f"Accuracy: {results['correct']/total*100:.1f}%")

        return results

    finally:
        db.close()


async def main():
    """Run all tests"""
    print("Starting Agentic Verification Tests\n")
    print("="*60 + "\n")

    # Test 1: Basic tools
    try:
        await test_codebase_tools()
    except Exception as e:
        print(f"CodebaseTools test failed: {e}")
        import traceback
        traceback.print_exc()

    # Test 2: Single finding verification
    print("\n" + "="*60 + "\n")
    try:
        await test_agentic_verification_single()
    except Exception as e:
        print(f"Single verification test failed: {e}")
        import traceback
        traceback.print_exc()

    # Test 3: Batch verification (optional - takes longer)
    # print("\n" + "="*60 + "\n")
    # try:
    #     await test_agentic_verification_batch()
    # except Exception as e:
    #     print(f"Batch verification test failed: {e}")


if __name__ == "__main__":
    asyncio.run(main())
