-- Migration: Add pause/resume support to tuning runs
-- Run this after stopping the app

ALTER TABLE tuning_runs ADD COLUMN is_paused BOOLEAN DEFAULT 0;
ALTER TABLE tuning_runs ADD COLUMN pause_requested_at TIMESTAMP;
ALTER TABLE tuning_runs ADD COLUMN resumed_at TIMESTAMP;

-- Status can now be: 'pending', 'running', 'paused', 'completed', 'failed', 'cancelled'
