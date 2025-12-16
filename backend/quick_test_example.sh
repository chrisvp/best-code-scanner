#!/bin/bash
# Quick demo of prompt testing framework

echo "========================================="
echo "Verification Prompt Testing Demo"
echo "========================================="
echo ""
echo "This demo tests how different prompts affect model accuracy"
echo "on 3 ground-truth vulnerability test cases."
echo ""

# Test 1: One finding, one model, one prompt
echo "Test 1: Single test (Finding 221 with gpt-oss-120b using math_focus)"
echo "----------------------------------------------------------------------"
python test_verification_prompts.py \
    --finding 221 \
    --model gpt-oss-120b \
    --prompt math_focus \
    --output /tmp/demo_test1.json

echo ""
echo "Test 2: All prompts for one finding (Finding 221 with gpt-oss-120b)"
echo "-------------------------------------------------------------------"
python test_verification_prompts.py \
    --finding 221 \
    --model gpt-oss-120b \
    --output /tmp/demo_test2.json

echo ""
echo "Analyzing results from Test 2..."
python analyze_prompt_results.py /tmp/demo_test2.json

echo ""
echo "========================================="
echo "Demo complete!"
echo "========================================="
echo ""
echo "To run full test matrix (all findings × all models × all prompts):"
echo "  python test_verification_prompts.py"
echo ""
echo "To test specific combinations:"
echo "  python test_verification_prompts.py --finding 213 --model mistral-small"
echo "  python test_verification_prompts.py --prompt uefi_expert"
echo ""
echo "Results saved to /tmp/verification_test_results.json"
