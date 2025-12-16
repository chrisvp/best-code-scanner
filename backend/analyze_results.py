#!/usr/bin/env python3
"""Comprehensive analysis of all model test results."""
import json
from pathlib import Path
from collections import defaultdict

def load_all_results():
    """Load results from all models."""
    results_dir = Path("/tmp/test_results")
    models = [
        "gpt-oss-120b",
        "mistral-small",
        "gemma-3-27b-it",
        "llama3.3-70b-instruct",
        "phi-4",
        "devstral-small-2-24b-instruct-test"
    ]

    all_results = {}
    for model in models:
        result_file = results_dir / f"{model}_results.json"
        if result_file.exists():
            with open(result_file) as f:
                all_results[model] = json.load(f)

    return all_results

def analyze_by_model(all_results):
    """Analyze performance by model."""
    print("=" * 80)
    print("OVERALL MODEL PERFORMANCE")
    print("=" * 80)
    print()

    model_stats = []
    for model, results in sorted(all_results.items()):
        total = len(results)
        successful = [r for r in results if 'error' not in r]
        correct = [r for r in successful if r.get('correct')]

        # Calculate confidence stats
        confidences = [r['confidence'] for r in successful if r.get('confidence') is not None]
        avg_conf = sum(confidences) / len(confidences) if confidences else 0

        accuracy = (len(correct) / len(successful) * 100) if successful else 0

        model_stats.append({
            'model': model,
            'total': total,
            'successful': len(successful),
            'correct': len(correct),
            'accuracy': accuracy,
            'avg_confidence': avg_conf
        })

        print(f"{model:30s}")
        print(f"  Tests:      {total:3d}/260")
        print(f"  Successful: {len(successful):3d} ({len(successful)/total*100:.1f}%)")
        print(f"  Correct:    {len(correct):3d}/{len(successful)}")
        print(f"  Accuracy:   {accuracy:.1f}%")
        print(f"  Avg Conf:   {avg_conf:.1f}")
        print()

    return model_stats

def analyze_by_prompt(all_results):
    """Analyze which prompts work best overall."""
    print("=" * 80)
    print("PROMPT PERFORMANCE ACROSS ALL MODELS")
    print("=" * 80)
    print()

    # Aggregate by prompt
    prompt_stats = defaultdict(lambda: {'correct': 0, 'total': 0})

    for model, results in all_results.items():
        for result in results:
            if 'error' not in result:
                prompt_id = result.get('prompt_id')
                prompt_stats[prompt_id]['total'] += 1
                if result.get('correct'):
                    prompt_stats[prompt_id]['correct'] += 1

    # Sort by accuracy
    sorted_prompts = sorted(
        prompt_stats.items(),
        key=lambda x: x[1]['correct'] / x[1]['total'] if x[1]['total'] else 0,
        reverse=True
    )

    print(f"{'Prompt':<25s} {'Correct':>8s} {'Total':>8s} {'Accuracy':>10s}")
    print("-" * 55)

    for prompt_id, stats in sorted_prompts[:10]:  # Top 10
        acc = (stats['correct'] / stats['total'] * 100) if stats['total'] else 0
        print(f"{prompt_id:<25s} {stats['correct']:>8d} {stats['total']:>8d} {acc:>9.1f}%")

    print()
    return sorted_prompts

def analyze_model_by_prompt(all_results):
    """Best prompt for each model."""
    print("=" * 80)
    print("BEST PROMPT PER MODEL")
    print("=" * 80)
    print()

    for model, results in sorted(all_results.items()):
        # Group by prompt
        prompt_perf = defaultdict(lambda: {'correct': 0, 'total': 0})

        for result in results:
            if 'error' not in result:
                prompt_id = result.get('prompt_id')
                prompt_perf[prompt_id]['total'] += 1
                if result.get('correct'):
                    prompt_perf[prompt_id]['correct'] += 1

        # Find best
        best_prompt = max(
            prompt_perf.items(),
            key=lambda x: x[1]['correct'] / x[1]['total'] if x[1]['total'] else 0
        )

        best_id = best_prompt[0]
        best_stats = best_prompt[1]
        best_acc = (best_stats['correct'] / best_stats['total'] * 100) if best_stats['total'] else 0

        print(f"{model:30s} → {best_id:<20s} ({best_stats['correct']}/{best_stats['total']} = {best_acc:.1f}%)")

    print()

def analyze_by_finding(all_results):
    """Which findings are hardest to classify correctly."""
    print("=" * 80)
    print("FINDING DIFFICULTY (Sorted by accuracy)")
    print("=" * 80)
    print()

    # Aggregate by finding
    finding_stats = defaultdict(lambda: {'correct': 0, 'total': 0})

    for model, results in all_results.items():
        for result in results:
            if 'error' not in result:
                finding_id = result.get('finding_id')
                finding_stats[finding_id]['total'] += 1
                if result.get('correct'):
                    finding_stats[finding_id]['correct'] += 1

    # Sort by accuracy (hardest first)
    sorted_findings = sorted(
        finding_stats.items(),
        key=lambda x: x[1]['correct'] / x[1]['total'] if x[1]['total'] else 0
    )

    print(f"{'Finding':<30s} {'Correct':>8s} {'Total':>8s} {'Accuracy':>10s}")
    print("-" * 60)

    for finding_id, stats in sorted_findings:
        acc = (stats['correct'] / stats['total'] * 100) if stats['total'] else 0
        difficulty = "HARD" if acc < 40 else "MEDIUM" if acc < 70 else "EASY"
        print(f"{finding_id:<30s} {stats['correct']:>8d} {stats['total']:>8d} {acc:>9.1f}%  [{difficulty}]")

    print()

def generate_report():
    """Generate comprehensive report."""
    all_results = load_all_results()

    if not all_results:
        print("No results found!")
        return

    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 15 + "COMPREHENSIVE MODEL TESTING REPORT" + " " * 29 + "║")
    print("╚" + "═" * 78 + "╝")
    print()

    analyze_by_model(all_results)
    analyze_by_prompt(all_results)
    analyze_model_by_prompt(all_results)
    analyze_by_finding(all_results)

    print("=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)

if __name__ == '__main__':
    generate_report()
