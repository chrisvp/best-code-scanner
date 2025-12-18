-- Fix ground truth labels based on Opus audit of test cases
-- Migration: fix_ground_truth_labels_opus_audit
-- Date: 2025-12-18
-- Auditor: Claude Opus 4.5

-- Summary: Opus reviewed 25/100 test cases and identified 4 mislabeled cases
-- Overall accuracy improved from ~92% to ~96% after corrections

-- CRITICAL FIX: NULL pointer dereference was mislabeled as FALSE_POSITIVE
-- Case 51 (scan26_draft4756_CWE-476): Writes *Description before NULL check
-- This is a REAL vulnerability that could train models incorrectly
UPDATE tuning_test_cases
SET verdict = 'REAL'
WHERE id = 51;

-- CRITICAL FIX: Unchecked security operation was labeled as WEAKNESS
-- Case 91 (scan26_draft4790_CWE-252): Ignoring SetVariable return on security-critical UEFI vars
-- Can bypass secure boot - should be REAL not WEAKNESS
UPDATE tuning_test_cases
SET verdict = 'REAL'
WHERE id = 91;

-- RECLASSIFICATION: Platform-specific behavior
-- Case 48 (scan30_draft14404_CWE-476): Pointer arithmetic on NULL (undefined but works on x86 BIOS)
-- Not FALSE_POSITIVE, but platform-specific edge case = WEAKNESS
UPDATE tuning_test_cases
SET verdict = 'WEAKNESS'
WHERE id = 48;

-- RECLASSIFICATION: Not actually a vulnerability
-- Case 107 (scan26_draft4816_CWE-200): Vendor name in firmware is not a security issue
-- Should be FALSE_POSITIVE, not WEAKNESS
UPDATE tuning_test_cases
SET verdict = 'FALSE_POSITIVE'
WHERE id = 107;

-- Resulting distribution:
-- REAL: 35 (+2 critical vulnerabilities now correctly labeled)
-- FALSE_POSITIVE: 32
-- WEAKNESS: 33
--
-- Verdict confidence from audit:
-- REAL: 93.5% (most reliable)
-- FALSE_POSITIVE: 93.2% (generally reliable)
-- WEAKNESS: 89.9% (least consistent boundary)

COMMIT;
