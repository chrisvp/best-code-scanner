# Real-time Streaming & Pause/Resume for Benchmark Tuning

## Overview

The benchmark tuning system now supports **real-time result streaming** and **pause/resume/cancel controls**. Users can watch results appear live as tests complete and control the execution flow interactively.

## Features

### 1. Real-time Result Streaming
- Results appear instantly as each test completes (no more waiting for entire run)
- Live progress bar updates
- Animated result rows with fade-in effect
- Shows: model, prompt, test case, predicted vote, correct/incorrect, duration

### 2. Pause/Resume Controls
- **Pause**: Gracefully pauses after current test completes
- **Resume**: Continues from where it left off
- **Cancel**: Stops execution immediately, saves partial results

### 3. Browser Refresh Support
- SSE auto-reconnects if browser refreshes
- Loads existing results on reconnection
- Restores UI state from server

## Database Changes

Run this migration **after stopping the app**:

```bash
sqlite3 backend/data/scans.db < backend/migrations/add_tuning_pause_resume.sql
```

Or manually:
```sql
ALTER TABLE tuning_runs ADD COLUMN is_paused BOOLEAN DEFAULT 0;
ALTER TABLE tuning_runs ADD COLUMN pause_requested_at TIMESTAMP;
ALTER TABLE tuning_runs ADD COLUMN resumed_at TIMESTAMP;
```

## Architecture

### Backend Components

1. **TuningRunController** (`app/services/tuning/run_controller.py`)
   - Singleton managing run state across requests
   - Holds pause/cancel events and SSE subscribers
   - Broadcasts events to all connected clients

2. **Modified PromptTuner** (`app/services/tuning/prompt_tuner.py`)
   - Sequential test execution (no longer uses `asyncio.gather`)
   - Checks cancel event before each test
   - Waits on pause event (blocks when paused)
   - Broadcasts results immediately after each test

3. **API Endpoints** (`app/api/tuning.py`)
   - `GET /tuning/runs/{run_id}/stream` - SSE endpoint for streaming
   - `POST /tuning/runs/{run_id}/pause` - Pause execution
   - `POST /tuning/runs/{run_id}/resume` - Resume execution
   - `POST /tuning/runs/{run_id}/cancel` - Cancel execution

### Frontend Components

- **EventSource connection** - Receives SSE events
- **Live results table** - Updates as results stream in
- **Progress bar** - Shows completion percentage
- **Control buttons** - Pause, Resume, Cancel
- **Toast notifications** - User feedback for state changes

## Event Types

### SSE Events Sent to Client

```javascript
{type: 'connected', run: {...}}          // Initial connection
{type: 'result', data: {...}, progress: {...}}  // New test result
{type: 'existing_result', data: {...}}   // Existing result (on reconnect)
{type: 'paused', message: '...'}         // Run paused
{type: 'resumed', message: '...'}        // Run resumed
{type: 'cancelled', message: '...'}      // Run cancelled
{type: 'completed', message: '...'}      // Run finished
{type: 'heartbeat'}                      // Keep-alive (every 30s)
```

## Usage

### Starting a Benchmark

1. Select prompts, test cases, and models
2. Click "Run Tests"
3. Results stream in real-time
4. Progress bar updates live

### Pausing/Resuming

- Click "Pause" to pause after current test completes
- Click "Resume" to continue
- State persists across browser refreshes

### Cancelling

- Click "Cancel" to stop immediately
- Partial results are saved
- Can view results of completed tests

## Implementation Notes

### Pause Behavior
- **Graceful pause**: Completes current test before pausing
- Ensures data consistency (no half-completed tests)
- UI shows "Pausing after current test..." message

### Result Streaming
- Each test result broadcasts immediately
- No batching or delays
- Results appear in reverse chronological order (newest first)
- Table limited to showing last 50 results (for performance)

### Connection Management
- Auto-reconnect on connection failure (3s delay)
- Heartbeat every 30s to keep connection alive
- Proper cleanup on run completion
- Multiple clients can watch same run

### Error Handling
- Failed tests still stream but marked with errors
- Partial results preserved on cancellation
- Connection failures trigger toast notification and retry
- Run status persists in database

## Testing

### Test Real-time Streaming
1. Start a benchmark with 50+ tests
2. Watch results appear one by one
3. Verify progress bar updates smoothly

### Test Pause/Resume
1. Start a benchmark
2. Click "Pause" mid-run
3. Verify it pauses after current test
4. Click "Resume"
5. Verify it continues from where it left off

### Test Browser Refresh
1. Start a benchmark
2. Refresh browser mid-run
3. Verify it reconnects and shows existing results
4. Verify new results continue streaming

### Test Cancellation
1. Start a benchmark
2. Click "Cancel" mid-run
3. Verify it stops immediately
4. Verify partial results are viewable
5. Verify run status is "cancelled"

## Troubleshooting

### SSE Connection Issues
- Check browser console for EventSource errors
- Verify `/tuning/runs/{run_id}/stream` endpoint is accessible
- Check for proxy/CDN interference with SSE
- Ensure proper CORS headers if using different domain

### Pause Not Working
- Check database `is_paused` column updates
- Verify TuningRunController state exists
- Check for errors in PromptTuner execution
- Verify pause event is being cleared/set properly

### Results Not Streaming
- Check if broadcast_event is being called
- Verify subscribers list is not empty
- Check for queue overflow (maxsize=100)
- Verify database commits after each test

## Future Enhancements

- [ ] Add "Restart Run" button for failed runs
- [ ] Export results as CSV/JSON
- [ ] Chart visualization of results (accuracy by model/prompt)
- [ ] Estimated time remaining calculation
- [ ] Concurrent runs dashboard
- [ ] Configurable result table row limit
- [ ] Sound notification on completion
- [ ] Email notification for long runs
