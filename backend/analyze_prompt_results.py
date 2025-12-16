#!/usr/bin/env python3
"""
Analyze results from prompt variation testing.

Usage:
    python analyze_prompt_results.py /tmp/verification_test_results.json
"""

import json
import sys
from collections import defaultdict
from typing import Dict, List

def load_results(filepath: str) -> List[Dict]:
    """Load test results from JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)

def analyze_by_finding(results: List[Dict]):
    """Analyze which prompts work best for each finding."""
    print("\n" + "="*80)
    print("ANALYSIS BY FINDING")
    print("="*80)

    by_finding = defaultdict(lambda: defaultdict(list))

    for r in results:
        if 'error' in r:
            continue
        finding_id = r['finding_id']
        prompt = r['prompt_variant']
        by_finding[finding_id][prompt].append(r)

    for finding_id in sorted(by_finding.keys()):
        print(f"\nFinding {finding_id}:")
        print(f"Ground truth: {results[0]['ground_truth']}")  # All should be same for a finding

        prompt_stats = {}
        for prompt, runs in by_finding[finding_id].items():
            correct = sum(1 for r in runs if r['correct'])
            total = len(runs)
            prompt_stats[prompt] = (correct, total, correct/total if total > 0 else 0)

        # Sort by accuracy
        for prompt, (correct, total, pct) in sorted(prompt_stats.items(),
                                                     key=lambda x: x[1][2],
                                                     reverse=True):
            print(f"  {prompt:20s}: {correct}/{total} ({100*pct:.1f}%)")

def analyze_by_model(results: List[Dict]):
    """Analyze which prompts work best for each model."""
    print("\n" + "="*80)
    print("ANALYSIS BY MODEL")
    print("="*80)

    by_model = defaultdict(lambda: defaultdict(list))

    for r in results:
        if 'error' in r:
            continue
        model = r['model']
        prompt = r['prompt_variant']
        by_model[model][prompt].append(r)

    for model in sorted(by_model.keys()):
        print(f"\n{model}:")

        prompt_stats = {}
        for prompt, runs in by_model[model].items():
            correct = sum(1 for r in runs if r['correct'])
            total = len(runs)
            prompt_stats[prompt] = (correct, total, correct/total if total > 0 else 0)

        # Sort by accuracy
        for prompt, (correct, total, pct) in sorted(prompt_stats.items(),
                                                     key=lambda x: x[1][2],
                                                     reverse=True):
            status = "✓" if pct == 1.0 else "⚠" if pct >= 0.5 else "✗"
            print(f"  {status} {prompt:20s}: {correct}/{total} ({100*pct:.1f}%)")

def analyze_confidence_calibration(results: List[Dict]):
    """Analyze if confidence correlates with correctness."""
    print("\n" + "="*80)
    print("CONFIDENCE CALIBRATION")
    print("="*80)

    by_model = defaultdict(lambda: {"correct": [], "incorrect": []})

    for r in results:
        if 'error' in r or r['confidence'] is None:
            continue

        model = r['model']
        if r['correct']:
            by_model[model]["correct"].append(r['confidence'])
        else:
            by_model[model]["incorrect"].append(r['confidence'])

    for model in sorted(by_model.keys()):
        stats = by_model[model]

        avg_correct = sum(stats["correct"]) / len(stats["correct"]) if stats["correct"] else 0
        avg_incorrect = sum(stats["incorrect"]) / len(stats["incorrect"]) if stats["incorrect"] else 0

        print(f"\n{model}:")
        print(f"  Avg confidence when CORRECT: {avg_correct:.1f}")
        print(f"  Avg confidence when INCORRECT: {avg_incorrect:.1f}")
        print(f"  Calibration gap: {avg_correct - avg_incorrect:.1f} points")

        if avg_incorrect > avg_correct:
            print(f"  ⚠ WARNING: Model MORE confident when WRONG (overconfident)")
        elif avg_correct > avg_incorrect + 10:
            print(f"  ✓ Good calibration (more confident when correct)")

def show_interesting_cases(results: List[Dict]):
    """Show cases where prompt made a difference."""
    print("\n" + "="*80)
    print("INTERESTING CASES (Prompt Impact)")
    print("="*80)

    # Group by (finding, model)
    by_case = defaultdict(list)

    for r in results:
        if 'error' in r:
            continue
        key = (r['finding_id'], r['model'])
        by_case[key].append(r)

    for (finding_id, model), runs in sorted(by_case.items()):
        # Check if different prompts gave different results
        votes = set(r['model_vote'] for r in runs if r['model_vote'])

        if len(votes) > 1:  # Prompts caused different votes
            print(f"\nFinding {finding_id} with {model}:")
            print(f"  Ground truth: {runs[0]['ground_truth']}")

            for r in runs:
                correct_mark = "✓" if r['correct'] else "✗"
                print(f"  {correct_mark} {r['prompt_variant']:20s} → {r['model_vote']} (conf: {r['confidence']})")

def recommend_best_prompts(results: List[Dict]):
    """Recommend best prompts overall and per-model."""
    print("\n" + "="*80)
    print("RECOMMENDATIONS")
    print("="*80)

    # Overall best prompt
    prompt_stats = defaultdict(lambda: {"correct": 0, "total": 0})

    for r in results:
        if 'error' in r:
            continue
        prompt = r['prompt_variant']
        prompt_stats[prompt]["total"] += 1
        if r['correct']:
            prompt_stats[prompt]["correct"] += 1

    best_overall = max(prompt_stats.items(),
                      key=lambda x: x[1]["correct"]/x[1]["total"] if x[1]["total"] > 0 else 0)

    print(f"\nBest prompt overall:")
    print(f"  '{best_overall[0]}' - {best_overall[1]['correct']}/{best_overall[1]['total']} "
          f"({100*best_overall[1]['correct']/best_overall[1]['total']:.1f}%)")

    # Best prompt per model
    by_model = defaultdict(lambda: defaultdict(lambda: {"correct": 0, "total": 0}))

    for r in results:
        if 'error' in r:
            continue
        model = r['model']
        prompt = r['prompt_variant']
        by_model[model][prompt]["total"] += 1
        if r['correct']:
            by_model[model][prompt]["correct"] += 1

    print(f"\nBest prompt per model:")
    for model in sorted(by_model.keys()):
        best = max(by_model[model].items(),
                  key=lambda x: x[1]["correct"]/x[1]["total"] if x[1]["total"] > 0 else 0)
        pct = 100 * best[1]["correct"] / best[1]["total"]
        print(f"  {model:20s}: '{best[0]}' ({best[1]['correct']}/{best[1]['total']}, {pct:.1f}%)")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <results.json>")
        sys.exit(1)

    results_file = sys.argv[1]
    results = load_results(results_file)

    print(f"\nLoaded {len(results)} test results from {results_file}")

    # Run all analyses
    analyze_by_finding(results)
    analyze_by_model(results)
    analyze_confidence_calibration(results)
    show_interesting_cases(results)
    recommend_best_prompts(results)

if __name__ == "__main__":
    main()
