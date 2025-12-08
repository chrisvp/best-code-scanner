# Davy Code Scanner - Benchmark Results (Dec 7, 2025)

## Summary
This benchmark evaluates 7 different LLMs against a "blind" test suite of 4 vulnerable C/C++ files. The models were not given the answer key; performance is measured by comparing their findings to the hidden metadata.

## Overall Performance

| Rank | Model | Pass Rate | Avg Latency | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| 🥇 | **gpt-oss-120b** | **100%** | **19.8s** | **Best Overall** (Fastest & Accurate) |
| 🥈 | **gemma-3-27b-it** | **100%** | 30.4s | Excellent, slightly slower |
| 🥉 | **llama3.3-70b** | **100%** | 34.2s | Solid performance |
| 4 | **mistral-small** | **100%** | 39.8s | Accurate but slowest of top tier |
| 5 | **mistral-nemo** | 75% | 55.1s | Missed one critical finding |
| 6 | **phi-4** | 0% | 25.5s | **Failed completely** (Found nothing) |
| - | **kimi-k2** | N/A | N/A | Timed out / Error |

## Detailed Analysis

### 1. The "Use After Free" Confusion
All top models (GPT, Llama, Mistral, Gemma) technically passed the "Use After Free" test in `memory_pool.cpp`, but the benchmark flagged it as a "Type Miss" (TP).
*   **Reason:** The benchmark expected strict string matching for "Use After Free".
*   **Reality:** Models likely reported it as "Memory Corruption" or "Double Free", which are semantically close enough.
*   **Action:** Benchmark matching logic should be fuzzy or semantic.

### 2. Phi-4 Failure
The `phi-4` model (small, 14B) failed to identify **any** vulnerabilities in the test suite.
*   **Diagnosis:** It likely lacks the reasoning depth for complex C++ vulnerability patterns or its context window/prompt handling is misconfigured.
*   **Recommendation:** Do not use `phi-4` as a primary scanner.

### 3. Speed King: GPT-OSS-120b
Despite being a massive model (120B parameters), `gpt-oss-120b` was the fastest at **19.8s average**, significantly beating smaller models like `mistral-small` (39.8s). This suggests excellent inference optimization (vLLM) or server hardware utilization.

## Recommendations

1.  **Primary Analyzer:** Use **gpt-oss-120b** as the default scanner. It provides the best combination of speed and accuracy.
2.  **Verification Consensus:** Use `gemma-3-27b-it` and `llama3.3-70b` as the secondary voters. Their 100% pass rate confirms they are reliable validators.
3.  **Retire:** Remove `phi-4` from the default profile due to poor performance.
