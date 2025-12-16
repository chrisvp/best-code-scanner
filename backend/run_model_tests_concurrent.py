#!/usr/bin/env python3
"""
Concurrent test executor that runs one model through all prompt/finding combinations.

Usage: python run_model_tests_concurrent.py <model_name> [concurrency]
"""

import json
import requests
import sys
import time
import re
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
warnings.filterwarnings('ignore')

# Global lock for printing
print_lock = Lock()

def load_test_data():
    """Load findings and prompts from library."""
    with open('test_library/findings.json') as f:
        findings = json.load(f)
    with open('test_library/prompts.json') as f:
        prompts = json.load(f)
    return findings, prompts

def parse_response(text):
    """Extract vote and confidence from model response."""
    # Strip thinking tags
    text_clean = re.sub(r'<thinking>.*?</thinking>', '', text, flags=re.DOTALL)
    text_clean = re.sub(r'<think>.*?</think>', '', text_clean, flags=re.DOTALL)

    # Find vote
    vote = None
    for category in ['FALSE_POSITIVE', 'REAL', 'NEEDS_VERIFIED', 'WEAKNESS']:
        if category.lower() in text_clean.lower() or category.replace('_', ' ').lower() in text_clean.lower():
            vote = category
            break

    # Find confidence
    confidence = None
    conf_match = re.search(r'confidence[:\s]+(\d+)', text_clean, re.IGNORECASE)
    if conf_match:
        try:
            confidence = int(conf_match.group(1))
        except:
            pass

    return vote, confidence

def run_single_test(model_name, test_num, total_tests, finding_id, finding, prompt_id, prompt_template):
    """Run a single test."""
    # Format prompt
    prompt = prompt_template.format(
        code=finding['code'],
        claim=finding['claim'],
        issue=finding['issue'],
        file=finding['file']
    )

    # Call API
    try:
        response = requests.post(
            'https://davy.labs.lenovo.com:5000/v1/chat/completions',
            json={
                'model': model_name,
                'messages': [{'role': 'user', 'content': prompt}],
                'temperature': 0.1,
                'max_tokens': 1000
            },
            headers={'Authorization': 'Bearer testkeyforchrisvp'},
            verify=False,
            timeout=90
        )

        if response.status_code == 200:
            data = response.json()
            response_text = data['choices'][0]['message']['content']

            vote, confidence = parse_response(response_text)
            correct = (vote == finding['verdict'])

            result = {
                'test_num': test_num,
                'finding_id': finding_id,
                'prompt_id': prompt_id,
                'ground_truth': finding['verdict'],
                'model_vote': vote,
                'confidence': confidence,
                'correct': correct
            }

            status = '✓' if correct else '✗'
            with print_lock:
                print(f"{status} Test {test_num}/{total_tests}: {finding_id} + {prompt_id} → {vote}")

            return result
        else:
            result = {
                'test_num': test_num,
                'finding_id': finding_id,
                'prompt_id': prompt_id,
                'error': f'HTTP {response.status_code}'
            }
            with print_lock:
                print(f"✗ Test {test_num}/{total_tests}: HTTP {response.status_code}")
            return result

    except Exception as e:
        result = {
            'test_num': test_num,
            'finding_id': finding_id,
            'prompt_id': prompt_id,
            'error': str(e)
        }
        with print_lock:
            print(f"✗ Test {test_num}/{total_tests}: {str(e)[:50]}")
        return result

def test_model(model_name, max_workers=4):
    """Run all tests for one model with concurrent execution."""
    findings, prompts = load_test_data()

    total_tests = len(findings) * len(prompts)

    print(f"Testing {model_name}: {total_tests} tests ({len(findings)} findings × {len(prompts)} prompts)")
    print(f"Concurrency: {max_workers} requests at a time")
    print("="*80)

    # Build all test cases
    test_cases = []
    test_num = 0
    for finding_id, finding in findings.items():
        for prompt_id, prompt_template in prompts.items():
            test_num += 1
            test_cases.append((test_num, finding_id, finding, prompt_id, prompt_template))

    # Run tests concurrently
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                run_single_test,
                model_name,
                test_num,
                total_tests,
                finding_id,
                finding,
                prompt_id,
                prompt_template
            ): test_num
            for test_num, finding_id, finding, prompt_id, prompt_template in test_cases
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)

    # Sort results by test number
    results.sort(key=lambda x: x['test_num'])

    # Save results
    output_file = f'/tmp/test_results/{model_name}_results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Calculate stats
    successful = [r for r in results if 'error' not in r]
    correct = [r for r in successful if r.get('correct')]

    print("\n" + "="*80)
    print(f"COMPLETED: {model_name}")
    print(f"  Total tests: {len(results)}")
    print(f"  Successful: {len(successful)}")
    print(f"  Correct: {len(correct)}")
    print(f"  Accuracy: {100*len(correct)/len(successful) if successful else 0:.1f}%")
    print(f"  Results: {output_file}")
    print("="*80)

    return {
        'model': model_name,
        'total': len(results),
        'successful': len(successful),
        'correct': len(correct),
        'accuracy': 100*len(correct)/len(successful) if successful else 0
    }

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python run_model_tests_concurrent.py <model_name> [concurrency]")
        sys.exit(1)

    model = sys.argv[1]
    concurrency = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    test_model(model, max_workers=concurrency)
