-- Add enricher output mode configuration to scan_profiles
-- This allows enricher to use guided_json, json, or markers format based on profile config

ALTER TABLE scan_profiles ADD COLUMN enricher_output_mode VARCHAR DEFAULT 'markers';
ALTER TABLE scan_profiles ADD COLUMN enricher_json_schema TEXT;

-- Set default output mode to guided_json for existing profiles
-- (markers will still work as fallback in code)
UPDATE scan_profiles SET enricher_output_mode = 'guided_json' WHERE enricher_output_mode IS NULL;
