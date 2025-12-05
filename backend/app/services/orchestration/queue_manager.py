"""
Global LLM Queue Manager

Manages all LLM requests across the system with per-model concurrency limits.
Provides real-time status updates for live monitoring.
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum
import uuid
import logging

logger = logging.getLogger(__name__)


class RequestStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


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
                # Move from queued to running
                queue.queued.remove(request)
                request.status = RequestStatus.RUNNING
                request.started_at = datetime.now()
                queue.running.append(request)
                await self._notify_subscribers("started", request)

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
            "models": list(self._model_queues.keys())
        }


# Global singleton instance
queue_manager = GlobalQueueManager()
