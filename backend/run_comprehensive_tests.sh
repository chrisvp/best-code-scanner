#!/bin/bash
# Execute comprehensive model testing using parallel agents
# This runs 1,300 tests: 5 models × 20 prompts × 13 findings

echo "=================================="
echo "COMPREHENSIVE MODEL TESTING"
echo "=================================="
echo ""
echo "Test Matrix:"
echo "  Models: 5 (gpt-oss-120b, mistral-small, gemma-3-27b-it, llama3.3-70b, phi-4)"
echo "  Prompts: 20 (10 structure + 10 new styles)"
echo "  Findings: 13 test cases"
echo "  Total: 1,300 tests"
echo ""
echo "Execution strategy: Batched parallel execution"
echo "  - Run models in parallel (5 concurrent)"
echo "  - Each model tests all prompts sequentially"
echo "  - Estimated time: 2-3 hours"
echo ""

# Create results directory
mkdir -p /tmp/comprehensive_results

# Function to run tests for one model
run_model_tests() {
    local model=$1
    local output_file="/tmp/comprehensive_results/${model}_results.json"

    echo "[$(date '+%H:%M:%S')] Starting tests for $model..."

    python3 << EOF
import json
import requests
import time
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Load test plan
with open('/tmp/comprehensive_test_plan.json') as f:
    plan = json.load(f)

with open('/tmp/test_findings.json') as f:
    findings = json.load(f)

with open('/tmp/test_prompts.json') as f:
    prompts = json.load(f)

model = "$model"
results = []

# Filter tests for this model
tests = [t for t in plan['test_matrix'] if t['model'] == model]
total = len(tests)

print(f"Running {total} tests for {model}")

for i, test in enumerate(tests):
    finding_id = str(test['finding_id'])
    prompt_key = test['prompt']

    finding = findings[finding_id]
    prompt_template = prompts[prompt_key]

    # Format prompt
    prompt = prompt_template.format(
        code=finding['code'],
        claim=finding['claim'],
        issue=finding['issue'],
        file_path=finding['file_path'],
        line=finding['line']
    )

    # Call API
    try:
        response = requests.post(
            'https://davy.labs.lenovo.com:5000/v1/chat/completions',
            json={
                'model': model,
                'messages': [{'role': 'user', 'content': prompt}],
                'temperature': 0.1,
                'max_tokens': 1000
            },
            headers={'Authorization': 'Bearer testkeyforchrisvp'},
            verify=False,
            timeout=60
        )

        if response.status_code == 200:
            data = response.json()
            response_text = data['choices'][0]['message']['content']

            # Parse vote
            import re
            vote = None
            confidence = None

            # Strip thinking tags
            text_clean = re.sub(r'<thinking>.*?</thinking>', '', response_text, flags=re.DOTALL)

            # Look for vote
            for category in ['FALSE_POSITIVE', 'REAL', 'NEEDS_VERIFIED', 'WEAKNESS']:
                if category.lower() in text_clean.lower():
                    vote = category
                    break

            # Look for confidence
            conf_match = re.search(r'confidence[:\s]+(\d+)', text_clean, re.IGNORECASE)
            if conf_match:
                confidence = int(conf_match.group(1))

            correct = (vote == finding['verdict'])

            results.append({
                'test_id': test['test_id'],
                'model': model,
                'prompt': prompt_key,
                'finding_id': finding_id,
                'ground_truth': finding['verdict'],
                'model_vote': vote,
                'confidence': confidence,
                'correct': correct,
                'response': response_text[:500]
            })

            if (i+1) % 10 == 0:
                print(f"  Progress: {i+1}/{total} ({100*(i+1)//total}%)")
        else:
            results.append({
                'test_id': test['test_id'],
                'model': model,
                'prompt': prompt_key,
                'finding_id': finding_id,
                'error': f'HTTP {response.status_code}'
            })
    except Exception as e:
        results.append({
            'test_id': test['test_id'],
            'model': model,
            'prompt': prompt_key,
            'finding_id': finding_id,
            'error': str(e)
        })

    time.sleep(0.2)  # Rate limiting

# Save results
with open('$output_file', 'w') as f:
    json.dump(results, f, indent=2)

print(f"Completed {len(results)} tests for {model}")
EOF

    echo "[$(date '+%H:%M:%S')] Completed $model"
}

export -f run_model_tests

# Run models in parallel (5 concurrent)
echo "Starting parallel execution..."
echo ""

parallel -j 5 run_model_tests ::: gpt-oss-120b mistral-small gemma-3-27b-it llama3.3-70b-instruct phi-4

echo ""
echo "=================================="
echo "ALL TESTS COMPLETED"
echo "=================================="
echo ""
echo "Results saved to: /tmp/comprehensive_results/"
echo ""
echo "Next: Run analysis to generate report"
