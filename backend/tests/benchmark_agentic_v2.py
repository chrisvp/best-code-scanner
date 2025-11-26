"""
Benchmark agentic verification with gpt-oss-120b.
Uses CORRECT ground truth with actual line numbers and snippets from the code.
"""
import asyncio
import sys
import os
import time
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.intelligence.codebase_tools import CodebaseTools
from app.services.intelligence.agent_runtime import AgenticVerifier
from app.services.orchestration.model_orchestrator import ModelPool, ModelConfig

# CORRECT ground truth - verified against actual source files
GROUND_TRUTH = {
    # True Positives - real vulnerabilities with correct locations
    'cmd_injection': {
        'expected': 'TP',
        'title': 'Command Injection via Unvalidated Hook',
        'type': 'CWE-78',
        'severity': 'Critical',
        'file': 'firmware_updater.cpp',
        'snippet': 'int result = system(command);',
        'reason': 'hook_name is concatenated into shell command without validation'
    },
    'uaf_process': {
        'expected': 'TP',
        'title': 'Use-After-Free in memory_pool_process_and_free',
        'type': 'CWE-416',
        'severity': 'Critical',
        'file': 'memory_pool.cpp',
        'snippet': 'process(ptr, header->size);',  # Line 413 - uses ptr after free at 410
        'reason': 'memory_pool_free(ptr) called before process(ptr) callback'
    },
    'format_string': {
        'expected': 'TP',
        'title': 'Format String in logger_user_message',
        'type': 'CWE-134',
        'severity': 'High',
        'file': 'logger_service.cpp',
        'snippet': 'printf(user_message);',
        'reason': 'User-controlled string passed directly to printf without format specifier'
    },

    # False Positives - safe code patterns
    'safe_alignment': {
        'expected': 'FP',
        'title': 'Integer Overflow in size alignment',
        'type': 'CWE-190',
        'severity': 'Medium',
        'file': 'memory_pool.cpp',
        'snippet': 'return (size + 7) & ~7;',
        'reason': 'Alignment operation - no exploitable overflow path'
    },
    'safe_vsnprintf': {
        'expected': 'FP',
        'title': 'Buffer Overflow with vsnprintf',
        'type': 'CWE-120',
        'severity': 'Medium',
        'file': 'firmware_updater.cpp',
        'snippet': 'vsnprintf(buffer, sizeof(buffer), format, args);',
        'reason': 'vsnprintf with sizeof(buffer) is safe - bounds checked'
    },
    'safe_strncpy': {
        'expected': 'FP',
        'title': 'Buffer Overflow with strncpy',
        'type': 'CWE-120',
        'severity': 'Medium',
        'file': 'firmware_updater.cpp',
        'snippet': 'strncpy(version_list, "", sizeof(version_list));',
        'reason': 'strncpy with sizeof limit is safe'
    },
}


async def test_model(model_name: str, base_url: str, test_cases: list, scan_path: str, max_steps: int = 5) -> dict:
    """Test a single model on the test cases."""
    print(f"\n{'='*60}")
    print(f"Testing model: {model_name}")
    print(f"{'='*60}")

    config = ModelConfig(
        name=model_name,
        base_url=base_url,
        api_key="testkeyforchrisvp",
        max_concurrent=1,
        max_tokens=2048
    )
    pool = ModelPool(config)
    await pool.start()
    tools = CodebaseTools(scan_id=27, root_dir=scan_path, db=None)
    verifier = AgenticVerifier(pool, tools, max_steps=max_steps)

    results = {
        'model': model_name,
        'findings': [],
        'correct': 0,
        'incorrect': 0,
        'tp_as_tp': 0,
        'tp_as_fp': 0,
        'fp_as_fp': 0,
        'fp_as_tp': 0,
        'total_time': 0,
        'avg_steps': 0,
    }

    total_steps = 0

    for test_id in test_cases:
        info = GROUND_TRUTH[test_id]
        print(f"\n--- {test_id}: {info['title'][:40]}... ---")
        print(f"Expected: {info['expected']}")

        start = time.time()
        try:
            result = await verifier.verify(
                title=info['title'],
                vuln_type=info['type'],
                severity=info['severity'],
                file_path=info['file'],
                line_number=0,  # Let agent find it via snippet search
                snippet=info['snippet'],
                reason=info['reason']
            )
            elapsed = time.time() - start

            verdict = 'TP' if result['verified'] else 'FP'
            correct = verdict == info['expected']

            steps = result.get('trace', '').count('=== Step')
            total_steps += steps

            print(f"Verdict: {verdict} (expected {info['expected']}) - {'CORRECT' if correct else 'WRONG'}")
            print(f"Confidence: {result['confidence']}")
            print(f"Time: {elapsed:.1f}s, Steps: {steps}")
            print(f"Reasoning: {result['reasoning'][:150]}...")

            results['findings'].append({
                'id': test_id,
                'expected': info['expected'],
                'verdict': verdict,
                'correct': correct,
                'confidence': result['confidence'],
                'time': elapsed,
                'steps': steps,
                'reasoning': result['reasoning'][:300]
            })

            if correct:
                results['correct'] += 1
            else:
                results['incorrect'] += 1

            if info['expected'] == 'TP':
                if verdict == 'TP':
                    results['tp_as_tp'] += 1
                else:
                    results['tp_as_fp'] += 1
            else:
                if verdict == 'FP':
                    results['fp_as_fp'] += 1
                else:
                    results['fp_as_tp'] += 1

            results['total_time'] += elapsed

        except Exception as e:
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()
            results['findings'].append({
                'id': test_id,
                'expected': info['expected'],
                'verdict': 'ERROR',
                'correct': False,
                'error': str(e)
            })
            results['incorrect'] += 1

    results['avg_steps'] = total_steps / len(test_cases) if test_cases else 0

    await pool.stop()
    return results


def print_summary(all_results: list):
    """Print comparison summary."""
    print("\n" + "="*70)
    print("BENCHMARK RESULTS SUMMARY")
    print("="*70)

    print(f"\n{'Model':<25} {'Accuracy':<10} {'TP->TP':<8} {'FP->FP':<8} {'Time':<10} {'Steps':<8}")
    print("-"*70)

    for r in all_results:
        total = r['correct'] + r['incorrect']
        accuracy = r['correct'] / total * 100 if total > 0 else 0
        tp_total = r['tp_as_tp'] + r['tp_as_fp']
        fp_total = r['fp_as_fp'] + r['fp_as_tp']
        print(f"{r['model']:<25} {accuracy:>6.1f}%   {r['tp_as_tp']}/{tp_total:<6} {r['fp_as_fp']}/{fp_total:<6} {r['total_time']:>6.1f}s   {r['avg_steps']:.1f}")

    print("\n" + "-"*70)
    print("Legend: TP->TP = True positives correctly verified")
    print("        FP->FP = False positives correctly rejected")
    print()

    # Detailed breakdown
    for r in all_results:
        print(f"\n{r['model']}:")
        for f in r['findings']:
            status = 'OK' if f.get('correct') else 'WRONG'
            print(f"  [{status}] {f['id']}: expected {f['expected']}, got {f.get('verdict', 'ERROR')}")


async def main():
    """Run benchmark on gpt-oss-120b only."""
    scan_path = "/mnt/c/Users/acrvp/code/code-scanner/backend/sandbox/27/vulnerable_cpp"
    base_url = "https://192.168.33.158:5000/v1"

    # Test all cases
    test_cases = list(GROUND_TRUTH.keys())
    print(f"Testing {len(test_cases)} cases: {test_cases}")
    print(f"Ground truth: {[GROUND_TRUTH[t]['expected'] for t in test_cases]}")

    all_results = []

    # Only test gpt-oss-120b since mistral-small performed poorly
    result = await test_model("gpt-oss-120b", base_url, test_cases, scan_path, max_steps=5)
    all_results.append(result)

    print_summary(all_results)

    # Save results
    output = {
        'timestamp': datetime.now().isoformat(),
        'test_cases': test_cases,
        'ground_truth': GROUND_TRUTH,
        'results': all_results
    }

    with open('benchmark_results_v2.json', 'w') as f:
        json.dump(output, f, indent=2)

    print("\nResults saved to benchmark_results_v2.json")


if __name__ == "__main__":
    asyncio.run(main())
