"""
Shared state controller for tuning runs.
Manages pause/resume/cancel state and SSE subscribers.
"""

import asyncio
from typing import Dict, Optional, Set
from datetime import datetime


class TuningRunController:
    """Singleton controller for managing tuning run states"""

    _instance = None

    def __init__(self):
        self._runs: Dict[int, 'TuningRunController.RunState'] = {}

    class RunState:
        """State for a single tuning run"""

        def __init__(self, run_id: int):
            self.run_id = run_id
            self.pause_event = asyncio.Event()
            self.pause_event.set()  # Initially not paused
            self.cancel_event = asyncio.Event()
            self.subscribers: Set[asyncio.Queue] = set()
            self.current_test = None
            self.lock = asyncio.Lock()

    @classmethod
    def get_instance(cls):
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_run_state(self, run_id: int) -> Optional[RunState]:
        """Get state for a specific run"""
        return self._runs.get(run_id)

    def create_run_state(self, run_id: int) -> RunState:
        """Create and register a new run state"""
        state = self.RunState(run_id)
        self._runs[run_id] = state
        return state

    def cleanup_run(self, run_id: int):
        """Remove run state after completion"""
        if run_id in self._runs:
            # Close all subscriber queues
            state = self._runs[run_id]
            for queue in state.subscribers:
                queue.put_nowait({"type": "cleanup"})
            state.subscribers.clear()

            del self._runs[run_id]

    async def pause_run(self, run_id: int) -> bool:
        """Request pause for a run"""
        state = self.get_run_state(run_id)
        if state:
            state.pause_event.clear()
            return True
        return False

    async def resume_run(self, run_id: int) -> bool:
        """Resume a paused run"""
        state = self.get_run_state(run_id)
        if state:
            state.pause_event.set()
            return True
        return False

    async def cancel_run(self, run_id: int) -> bool:
        """Cancel a running or paused run"""
        state = self.get_run_state(run_id)
        if state:
            state.cancel_event.set()
            state.pause_event.set()  # Unblock if paused
            return True
        return False

    async def broadcast_event(self, run_id: int, event_data: dict):
        """Broadcast event to all SSE subscribers for this run"""
        state = self.get_run_state(run_id)
        if state:
            # Send to all subscribers
            dead_queues = set()
            for queue in state.subscribers:
                try:
                    queue.put_nowait(event_data)
                except asyncio.QueueFull:
                    # Queue is full, skip this subscriber
                    dead_queues.add(queue)

            # Remove dead queues
            state.subscribers -= dead_queues
