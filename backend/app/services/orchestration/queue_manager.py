"""
Global LLM Queue Manager

Manages all LLM requests across the system with per-model concurrency limits.
Provides real-time status updates for live monitoring.

Key features:
- Per-model concurrency limits via semaphores
- Scan state validation: requests are skipped if their scan is no longer running
- Cancellation support: cancel all requests for a specific scan
- Real-time SSE updates for monitoring
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable, Awaitable, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid
import logging
import weakref

logger = logging.getLogger(__name__)

# Valid scan states that should allow queued requests to proceed
ACTIVE_SCAN_STATES = {"running", "queued"}


class PhaseSlotAllocator:
    """
    Auto-adaptive slot allocation for scan phases.

    Dynamically allocates concurrency slots between scanner, verifier, and enricher
    phases based on work queue depths. Prioritizes scanner phase for throughput,
    but gives slots to verification and enrichment as findings accumulate.

    Allocation strategy:
    - Scanner: Gets base 70% of slots, can take all 100% if no findings pending
    - Verifier: Gets up to 30% of slots once draft findings exist
    - Enricher: Gets up to 10% of slots once verified findings exist

    The allocator redistributes dynamically based on actual queue depths:
    - If no drafts pending, scanner gets verifier slots
    - If no verified pending, verifier can use enricher slots

    Percentages can be configured via GlobalSetting database entries:
    - phase_scanner_base_pct (default 70)
    - phase_verifier_max_pct (default 30)
    - phase_enricher_max_pct (default 10)
    """

    # Default allocation percentages (loaded from DB on first use)
    DEFAULT_SCANNER_PCT = 70
    DEFAULT_VERIFIER_PCT = 30
    DEFAULT_ENRICHER_PCT = 10

    def __init__(self):
        # Track phase queue depths per scan
        self._phase_depths: Dict[int, Dict[str, int]] = {}  # scan_id -> {phase: count}
        # Track allocated slots per scan per phase
        self._allocated: Dict[int, Dict[str, int]] = {}  # scan_id -> {phase: count}
        self._lock = asyncio.Lock()

    def register_scan(self, scan_id: int, total_slots: int):
        """Register a new scan with its total available slots"""
        self._phase_depths[scan_id] = {
            "scanner": 0,
            "verifier": 0,
            "enricher": 0
        }
        self._allocated[scan_id] = {
            "scanner": 0,
            "verifier": 0,
            "enricher": 0,
            "total_slots": total_slots
        }

    def unregister_scan(self, scan_id: int):
        """Unregister a scan when complete"""
        self._phase_depths.pop(scan_id, None)
        self._allocated.pop(scan_id, None)

    def update_queue_depth(self, scan_id: int, phase: str, depth: int):
        """Update the queue depth for a phase (used for adaptive allocation)"""
        if scan_id in self._phase_depths:
            self._phase_depths[scan_id][phase] = depth

    async def request_slot(self, scan_id: int, phase: str) -> bool:
        """
        Request a slot for a phase. Returns True if slot granted.

        Uses adaptive allocation based on queue depths.
        """
        async with self._lock:
            if scan_id not in self._allocated:
                return True  # No tracking for this scan, allow

            alloc = self._allocated[scan_id]
            depths = self._phase_depths.get(scan_id, {})
            total = alloc.get("total_slots", 10)

            # Calculate dynamic slot allocation
            scanner_slots, verifier_slots, enricher_slots = self._calculate_allocation(
                total, depths
            )

            # Check if this phase can have a slot
            if phase == "scanner":
                if alloc["scanner"] < scanner_slots:
                    alloc["scanner"] += 1
                    return True
            elif phase == "verifier":
                if alloc["verifier"] < verifier_slots:
                    alloc["verifier"] += 1
                    return True
            elif phase == "enricher":
                if alloc["enricher"] < enricher_slots:
                    alloc["enricher"] += 1
                    return True
            else:
                # Unknown phase, allow (chat, cleanup, etc.)
                return True

            return False

    def release_slot(self, scan_id: int, phase: str):
        """Release a slot for a phase"""
        if scan_id in self._allocated and phase in self._allocated[scan_id]:
            self._allocated[scan_id][phase] = max(0, self._allocated[scan_id][phase] - 1)

    def _load_percentages(self) -> tuple:
        """Load allocation percentages from database settings"""
        from app.core.database import SessionLocal
        from app.models.scanner_models import GlobalSetting

        db = SessionLocal()
        try:
            scanner_pct = GlobalSetting.get(db, "phase_scanner_base_pct", self.DEFAULT_SCANNER_PCT)
            verifier_pct = GlobalSetting.get(db, "phase_verifier_max_pct", self.DEFAULT_VERIFIER_PCT)
            enricher_pct = GlobalSetting.get(db, "phase_enricher_max_pct", self.DEFAULT_ENRICHER_PCT)
            return (int(scanner_pct) / 100, int(verifier_pct) / 100, int(enricher_pct) / 100)
        except Exception as e:
            logger.warning(f"Failed to load phase percentages from DB: {e}")
            return (self.DEFAULT_SCANNER_PCT / 100, self.DEFAULT_VERIFIER_PCT / 100, self.DEFAULT_ENRICHER_PCT / 100)
        finally:
            db.close()

    def _calculate_allocation(
        self, total_slots: int, depths: Dict[str, int]
    ) -> tuple:
        """
        Calculate slot allocation based on queue depths.

        Returns (scanner_slots, verifier_slots, enricher_slots)
        """
        # Load current percentages from database
        base_scanner_pct, max_verifier_pct, max_enricher_pct = self._load_percentages()

        verifier_depth = depths.get("verifier", 0)
        enricher_depth = depths.get("enricher", 0)

        # Start with base allocation
        enricher_slots = 0
        verifier_slots = 0

        # Enricher gets slots if there's work pending
        if enricher_depth > 0:
            enricher_slots = max(1, int(total_slots * max_enricher_pct))

        # Verifier gets slots if there's work pending
        if verifier_depth > 0:
            verifier_slots = max(1, int(total_slots * max_verifier_pct))

        # Scanner gets the rest
        scanner_slots = total_slots - verifier_slots - enricher_slots

        # Ensure scanner always has at least 50% of slots
        min_scanner = max(1, int(total_slots * 0.5))
        if scanner_slots < min_scanner:
            # Take from verifier first, then enricher
            deficit = min_scanner - scanner_slots
            take_from_verifier = min(deficit, verifier_slots - 1) if verifier_slots > 1 else 0
            verifier_slots -= take_from_verifier
            deficit -= take_from_verifier
            if deficit > 0 and enricher_slots > 1:
                enricher_slots = max(1, enricher_slots - deficit)
            scanner_slots = total_slots - verifier_slots - enricher_slots

        return (scanner_slots, verifier_slots, enricher_slots)

    def get_allocation_status(self, scan_id: int) -> Dict[str, Any]:
        """Get current allocation status for a scan"""
        if scan_id not in self._allocated:
            return {}

        alloc = self._allocated[scan_id]
        depths = self._phase_depths.get(scan_id, {})
        total = alloc.get("total_slots", 10)

        scanner_max, verifier_max, enricher_max = self._calculate_allocation(
            total, depths
        )

        return {
            "total_slots": total,
            "scanner": {"used": alloc["scanner"], "max": scanner_max},
            "verifier": {"used": alloc["verifier"], "max": verifier_max},
            "enricher": {"used": alloc["enricher"], "max": enricher_max},
            "queue_depths": depths
        }


# Global phase slot allocator
phase_allocator = PhaseSlotAllocator()


class RequestStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"  # Scan no longer active when request was about to run
    CANCELLED = "cancelled"  # Actively cancelled while running


class RequestType(str, Enum):
    ANALYZER = "analyzer"
    VERIFIER = "verifier"
    ENRICHER = "enricher"
    AGENT = "agent"
    CHAT = "chat"
    CLEANUP = "cleanup"


@dataclass
class QueuedRequest:
    """Represents a request in the queue"""
    id: str
    model_name: str
    request_type: RequestType
    status: RequestStatus
    scan_id: Optional[int] = None
    finding_id: Optional[int] = None
    chunk_index: Optional[int] = None
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    tokens_used: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "model_name": self.model_name,
            "request_type": self.request_type.value,
            "status": self.status.value,
            "scan_id": self.scan_id,
            "finding_id": self.finding_id,
            "chunk_index": self.chunk_index,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
            "tokens_used": self.tokens_used,
            "wait_time_ms": (self.started_at - self.created_at).total_seconds() * 1000 if self.started_at else None,
            "run_time_ms": (self.completed_at - self.started_at).total_seconds() * 1000 if self.completed_at and self.started_at else None
        }


@dataclass
class ModelQueue:
    """Queue state for a single model"""
    model_name: str
    max_concurrent: int
    semaphore: asyncio.Semaphore
    queued: List[QueuedRequest] = field(default_factory=list)
    running: List[QueuedRequest] = field(default_factory=list)
    completed: List[QueuedRequest] = field(default_factory=list)  # Last N completed
    failed: List[QueuedRequest] = field(default_factory=list)  # Last N failed
    total_requests: int = 0
    total_tokens: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "max_concurrent": self.max_concurrent,
            "current_running": len(self.running),
            "queue_depth": len(self.queued),
            "total_requests": self.total_requests,
            "total_tokens": self.total_tokens,
            "queued": [r.to_dict() for r in self.queued],
            "running": [r.to_dict() for r in self.running],
            "recent_completed": [r.to_dict() for r in self.completed[-10:]],
            "recent_failed": [r.to_dict() for r in self.failed[-10:]]
        }


class GlobalQueueManager:
    """
    Singleton manager for all LLM requests across the application.
    Respects per-model concurrency limits and provides real-time status.
    """

    _instance: Optional["GlobalQueueManager"] = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self._model_queues: Dict[str, ModelQueue] = {}
        self._subscribers: List[asyncio.Queue] = []
        self._history_limit = 50  # Keep last N completed/failed per model
        self._cancelled_scans: Set[int] = set()  # Scans that have been cancelled/paused
        self._scan_state_checker: Optional[Callable[[int], Awaitable[Optional[str]]]] = None
        # Track running tasks for cancellation - maps request_id to (asyncio.Task, scan_id)
        self._running_tasks: Dict[str, tuple] = {}

    def _get_or_create_queue(self, model_name: str, max_concurrent: int = 2) -> ModelQueue:
        """Get existing queue or create new one for model"""
        if model_name not in self._model_queues:
            self._model_queues[model_name] = ModelQueue(
                model_name=model_name,
                max_concurrent=max_concurrent,
                semaphore=asyncio.Semaphore(max_concurrent)
            )
        return self._model_queues[model_name]

    def update_model_concurrency(self, model_name: str, max_concurrent: int):
        """Update concurrency limit for a model (creates new semaphore)"""
        if model_name in self._model_queues:
            queue = self._model_queues[model_name]
            queue.max_concurrent = max_concurrent
            queue.semaphore = asyncio.Semaphore(max_concurrent)

    def set_scan_state_checker(self, checker: Callable[[int], Awaitable[Optional[str]]]):
        """Set a callback to check scan state before processing requests.

        The checker should return the scan status string (e.g., 'running', 'paused', 'failed')
        or None if the scan doesn't exist.
        """
        self._scan_state_checker = checker

    def cancel_scan(self, scan_id: int, cancel_running: bool = True) -> Dict[str, Any]:
        """Mark a scan as cancelled. All pending requests for this scan will be skipped.

        Args:
            scan_id: The scan ID to cancel
            cancel_running: If True, also cancel in-flight requests (immediate cancellation)

        Returns stats about requests that were removed/cancelled.
        """
        self._cancelled_scans.add(scan_id)

        removed = {"queued": 0, "running_cancelled": 0, "models": []}

        # Remove queued requests for this scan from all model queues
        for model_name, queue in self._model_queues.items():
            before_count = len(queue.queued)
            queue.queued = [r for r in queue.queued if r.scan_id != scan_id]
            removed_count = before_count - len(queue.queued)

            if removed_count > 0:
                removed["queued"] += removed_count
                removed["models"].append(model_name)

        # Cancel running tasks if requested (immediate cancellation)
        if cancel_running:
            tasks_to_cancel = []
            for request_id, (task, task_scan_id) in list(self._running_tasks.items()):
                if task_scan_id == scan_id and not task.done():
                    tasks_to_cancel.append((request_id, task))

            for request_id, task in tasks_to_cancel:
                try:
                    task.cancel()
                    removed["running_cancelled"] += 1
                    logger.info(f"Cancelled running task {request_id} for scan {scan_id}")
                except Exception as e:
                    logger.error(f"Failed to cancel task {request_id}: {e}")

        logger.info(f"Cancelled scan {scan_id}: removed {removed['queued']} queued, cancelled {removed['running_cancelled']} running")
        return removed

    def uncancelled_scan(self, scan_id: int):
        """Remove a scan from the cancelled set (for resume functionality)."""
        self._cancelled_scans.discard(scan_id)

    async def _is_scan_active(self, scan_id: Optional[int]) -> bool:
        """Check if a scan is still active and should have its requests processed."""
        if scan_id is None:
            return True  # No scan_id means it's a standalone request (e.g., chat)

        # Check explicit cancellation first
        if scan_id in self._cancelled_scans:
            return False

        # Check scan state via callback if available
        if self._scan_state_checker:
            try:
                status = await self._scan_state_checker(scan_id)
                if status is None:
                    logger.warning(f"Scan {scan_id} not found, skipping request")
                    return False
                if status not in ACTIVE_SCAN_STATES:
                    logger.info(f"Scan {scan_id} is {status}, skipping request")
                    return False
            except Exception as e:
                logger.error(f"Error checking scan state for {scan_id}: {e}")
                # On error, allow the request to proceed
                return True

        return True

    async def _notify_subscribers(self, event_type: str, request: QueuedRequest):
        """Notify all subscribers of queue state change"""
        event = {
            "type": event_type,
            "timestamp": datetime.now().isoformat(),
            "request": request.to_dict(),
            "model_state": self._model_queues[request.model_name].to_dict() if request.model_name in self._model_queues else None
        }

        # Send to all subscribers, remove dead ones
        dead_subscribers = []
        for subscriber in self._subscribers:
            try:
                subscriber.put_nowait(event)
            except asyncio.QueueFull:
                dead_subscribers.append(subscriber)

        for dead in dead_subscribers:
            self._subscribers.remove(dead)

    def subscribe(self) -> asyncio.Queue:
        """Subscribe to queue updates. Returns a Queue that receives events."""
        queue = asyncio.Queue(maxsize=100)
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        """Unsubscribe from queue updates"""
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    async def enqueue(
        self,
        model_name: str,
        request_type: RequestType,
        func: Callable[[], Awaitable[Any]],
        max_concurrent: int = 2,
        scan_id: Optional[int] = None,
        finding_id: Optional[int] = None,
        chunk_index: Optional[int] = None,
        description: str = ""
    ) -> Any:
        """
        Enqueue an LLM request and wait for it to complete.
        Respects per-model concurrency limits.

        Args:
            model_name: Name of the model
            request_type: Type of request (analyzer, verifier, etc.)
            func: Async function to execute
            max_concurrent: Max concurrent requests for this model
            scan_id: Optional scan ID for tracking
            finding_id: Optional finding ID for tracking
            chunk_index: Optional chunk index for tracking
            description: Human-readable description

        Returns:
            Result of the function
        """
        queue = self._get_or_create_queue(model_name, max_concurrent)

        request = QueuedRequest(
            id=str(uuid.uuid4())[:8],
            model_name=model_name,
            request_type=request_type,
            status=RequestStatus.QUEUED,
            scan_id=scan_id,
            finding_id=finding_id,
            chunk_index=chunk_index,
            description=description
        )

        queue.queued.append(request)
        queue.total_requests += 1
        await self._notify_subscribers("queued", request)

        try:
            # Wait for semaphore (respects concurrency limit)
            async with queue.semaphore:
                # Check if scan is still active before running
                if not await self._is_scan_active(scan_id):
                    # Scan is no longer active, skip this request
                    queue.queued.remove(request)
                    request.status = RequestStatus.SKIPPED
                    request.completed_at = datetime.now()
                    request.error = "Scan no longer active"
                    queue.failed.append(request)  # Track skipped in failed for visibility

                    if len(queue.failed) > self._history_limit:
                        queue.failed = queue.failed[-self._history_limit:]

                    await self._notify_subscribers("skipped", request)
                    logger.info(f"Skipped request {request.id} for inactive scan {scan_id}")
                    return None

                # Move from queued to running
                queue.queued.remove(request)
                request.status = RequestStatus.RUNNING
                request.started_at = datetime.now()
                queue.running.append(request)
                await self._notify_subscribers("started", request)

                # Track the current task for cancellation support
                current_task = asyncio.current_task()
                if current_task and scan_id is not None:
                    self._running_tasks[request.id] = (current_task, scan_id)

                try:
                    result = await func()

                    # Mark completed
                    request.status = RequestStatus.COMPLETED
                    request.completed_at = datetime.now()
                    queue.running.remove(request)
                    queue.completed.append(request)

                    # Trim history
                    if len(queue.completed) > self._history_limit:
                        queue.completed = queue.completed[-self._history_limit:]

                    await self._notify_subscribers("completed", request)
                    return result

                except asyncio.CancelledError:
                    # Task was cancelled (e.g., scan paused with immediate cancel)
                    request.status = RequestStatus.CANCELLED
                    request.completed_at = datetime.now()
                    request.error = "Cancelled by user"
                    if request in queue.running:
                        queue.running.remove(request)
                    queue.failed.append(request)

                    if len(queue.failed) > self._history_limit:
                        queue.failed = queue.failed[-self._history_limit:]

                    await self._notify_subscribers("cancelled", request)
                    logger.info(f"Request {request.id} cancelled for scan {scan_id}")
                    return None  # Return None instead of raising to avoid error propagation

                except Exception as e:
                    # Mark failed
                    request.status = RequestStatus.FAILED
                    request.completed_at = datetime.now()
                    request.error = str(e)
                    queue.running.remove(request)
                    queue.failed.append(request)

                    # Trim history
                    if len(queue.failed) > self._history_limit:
                        queue.failed = queue.failed[-self._history_limit:]

                    await self._notify_subscribers("failed", request)
                    raise

                finally:
                    # Clean up task tracking
                    self._running_tasks.pop(request.id, None)

        except Exception as e:
            # Handle case where request was never started (shouldn't happen normally)
            if request in queue.queued:
                queue.queued.remove(request)
            raise

    def get_all_queues(self) -> Dict[str, Dict[str, Any]]:
        """Get state of all model queues"""
        return {
            name: queue.to_dict()
            for name, queue in self._model_queues.items()
        }

    def get_queue(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get state of a specific model queue"""
        if model_name in self._model_queues:
            return self._model_queues[model_name].to_dict()
        return None

    def get_global_stats(self) -> Dict[str, Any]:
        """Get aggregate stats across all models"""
        total_queued = sum(len(q.queued) for q in self._model_queues.values())
        total_running = sum(len(q.running) for q in self._model_queues.values())
        total_requests = sum(q.total_requests for q in self._model_queues.values())
        total_tokens = sum(q.total_tokens for q in self._model_queues.values())

        return {
            "total_models": len(self._model_queues),
            "total_queued": total_queued,
            "total_running": total_running,
            "total_requests": total_requests,
            "total_tokens": total_tokens,
            "models": list(self._model_queues.keys()),
            "cancelled_scans": list(self._cancelled_scans)
        }

    def clear_all(self) -> Dict[str, Any]:
        """Clear all queued and running requests (for cleanup after crashes/hangs).

        Returns stats about what was cleared.
        """
        cleared = {
            "queued": 0,
            "running": 0,
            "models_reset": [],
            "cancelled_scans_cleared": len(self._cancelled_scans)
        }

        # Clear cancelled scans tracking
        self._cancelled_scans.clear()

        for model_name, queue in self._model_queues.items():
            queued_count = len(queue.queued)
            running_count = len(queue.running)

            if queued_count > 0 or running_count > 0:
                cleared["queued"] += queued_count
                cleared["running"] += running_count
                cleared["models_reset"].append(model_name)

                # Clear the lists
                queue.queued.clear()
                queue.running.clear()

                # Reset the semaphore to max_concurrent (release any held slots)
                queue.semaphore = asyncio.Semaphore(queue.max_concurrent)

        logger.info(f"Queue cleared: {cleared}")
        return cleared


# Global singleton instance
queue_manager = GlobalQueueManager()
