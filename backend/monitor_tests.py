#!/usr/bin/env python3
"""Monitor test progress across all models."""
import json
import os
import time
from pathlib import Path

def check_progress():
    """Check progress of all test runs."""
    results_dir = Path("/tmp/test_results")

    models = [
        "gpt-oss-120b",
        "mistral-small",
        "gemma-3-27b-it",
        "llama3.3-70b-instruct",
        "phi-4"
    ]

    print("=" * 80)
    print("COMPREHENSIVE MODEL TESTING - PROGRESS")
    print("=" * 80)
    print()

    total_expected = 13 * 20  # 13 findings × 20 prompts = 260 tests per model

    for model in models:
        result_file = results_dir / f"{model}_results.json"

        if result_file.exists():
            try:
                with open(result_file) as f:
                    results = json.load(f)

                total = len(results)
                successful = len([r for r in results if 'error' not in r])
                correct = len([r for r in results if r.get('correct')])

                pct = (total / total_expected * 100) if total else 0
                acc = (correct / successful * 100) if successful else 0

                print(f"{model:30s} {total:3d}/{total_expected} ({pct:5.1f}%) | "
                      f"Success: {successful:3d} | Correct: {correct:3d} | Acc: {acc:5.1f}%")
            except:
                print(f"{model:30s} ERROR reading results")
        else:
            print(f"{model:30s} Not started yet")

    print()
    print("=" * 80)

if __name__ == '__main__':
    while True:
        check_progress()
        time.sleep(30)
