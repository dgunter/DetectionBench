"""In-memory sliding-window rate limiter and a global call budget.

Single-process state is fine here: the backend runs as one uvicorn worker
and every classification is stateless, so nothing needs to be shared.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindow:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            hits = self._hits[key]
            cutoff = now - self.window
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


class GlobalBudget:
    """Fixed-window global counter (e.g. N calls per hour across all clients)."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = window_seconds
        self._count = 0
        self._window_start = 0.0
        self._lock = threading.Lock()

    def allow(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            if now - self._window_start >= self.window:
                self._window_start = now
                self._count = 0
            if self._count >= self.limit:
                return False
            self._count += 1
            return True

    def remaining(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            if now - self._window_start >= self.window:
                return self.limit
            return max(self.limit - self._count, 0)

    def reset(self) -> None:
        with self._lock:
            self._count = 0
            self._window_start = 0.0
