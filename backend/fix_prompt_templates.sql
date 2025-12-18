-- Fix prompt templates to use correct vote values
-- Run with: sqlite3 data/scans.db < fix_prompt_templates.sql

BEGIN TRANSACTION;

-- Replace VERIFY with REAL in all prompt templates
UPDATE tuning_prompt_templates
SET template = REPLACE(template, 'VERIFY', 'REAL')
WHERE template LIKE '%VERIFY%';

-- Replace REJECT with FALSE_POSITIVE in all prompt templates
UPDATE tuning_prompt_templates
SET template = REPLACE(template, 'REJECT', 'FALSE_POSITIVE')
WHERE template LIKE '%REJECT%';

-- Also fix lowercase variants that might exist
UPDATE tuning_prompt_templates
SET template = REPLACE(template, 'verify', 'REAL')
WHERE template LIKE '%verify%';

UPDATE tuning_prompt_templates
SET template = REPLACE(template, 'reject', 'FALSE_POSITIVE')
WHERE template LIKE '%reject%';

COMMIT;

-- Show what changed
SELECT id, name,
  CASE
    WHEN template LIKE '%REAL%' OR template LIKE '%FALSE_POSITIVE%' THEN 'UPDATED'
    ELSE 'NO CHANGE'
  END as status
FROM tuning_prompt_templates
ORDER BY id;
