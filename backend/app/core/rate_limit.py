"""Rate-limit stores.

* ``InMemoryRateLimiter``: sliding window per key, bounded memory. Correct only
  for ONE application instance; in production it must be acknowledged with
  ``RATE_LIMIT_SINGLE_INSTANCE=true``.
* ``FirestoreRateLimiter``: fixed-window counters in the ``rate_limits``
  collection, incremented in a transaction, so every instance shares one
  budget. Documents carry ``expires_at`` for a Firestore TTL policy.
"""

from __future__ import annotations

from collections import deque
from datetime import UTC, datetime, timedelta
import hashlib
import threading
import time
from typing import Any, Protocol

from .config import Settings


class RateLimiter(Protocol):
    def hit(self, key: str) -> bool:
        """Records one request for ``key``; returns False when over the limit."""


class RateLimitUnavailableError(RuntimeError):
    pass


class InMemoryRateLimiter:
    def __init__(self, limit: int, window_seconds: int, max_keys: int = 10_000, clock=time.monotonic) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        for key in [k for k, q in self._hits.items() if not q or now - q[-1] >= self.window]:
            del self._hits[key]

    def hit(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            window = self._hits.setdefault(key, deque())
            while window and now - window[0] >= self.window:
                window.popleft()
            if len(window) >= self.limit:
                return False
            window.append(now)
            if len(self._hits) > self.max_keys:
                self._prune(now)
                if len(self._hits) > self.max_keys:
                    # Bounded memory under key flooding: evict oldest keys.
                    for stale in sorted(self._hits, key=lambda k: self._hits[k][-1])[: len(self._hits) - self.max_keys]:
                        del self._hits[stale]
            return True


# Striped per-process locks: requests for the same key from one instance queue
# locally instead of contending on the same Firestore counter document.
_KEY_LOCKS = [threading.Lock() for _ in range(64)]


class FirestoreRateLimiter:
    COLLECTION = "rate_limits"

    def __init__(self, limit: int, window_seconds: int, client: Any | None = None, clock=time.time) -> None:
        self.limit = limit
        self.window = window_seconds
        self._clock = clock
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            from .firestore import get_firestore_client

            self._client = get_firestore_client()
        return self._client

    def hit(self, key: str) -> bool:
        from google.cloud import firestore

        now = self._clock()
        window_index = int(now // self.window)
        digest = hashlib.sha256(key.encode()).hexdigest()[:40]
        ref = self.client.collection(self.COLLECTION).document(f"{digest}_{window_index}")
        expires_at = datetime.fromtimestamp((window_index + 1) * self.window, UTC) + timedelta(seconds=self.window)

        @firestore.transactional
        def increment(transaction) -> bool:
            snapshot = ref.get(transaction=transaction)
            count = int(snapshot.get("count")) if snapshot.exists else 0
            if count >= self.limit:
                return False
            transaction.set(ref, {"count": count + 1, "window": window_index, "expires_at": expires_at})
            return True

        try:
            with _KEY_LOCKS[int(digest[:8], 16) % len(_KEY_LOCKS)]:
                return increment(self.client.transaction(max_attempts=20))
        except Exception as exc:  # pragma: no cover - exercised via emulator tests
            raise RateLimitUnavailableError(str(exc)) from exc


def build_rate_limiter(settings: Settings) -> RateLimiter:
    backend = settings.rate_limit_backend.lower()
    if backend == "auto":
        backend = "firestore" if settings.database_mode.lower() == "firestore" else "memory"
    if backend == "firestore":
        return FirestoreRateLimiter(settings.rate_limit_requests, settings.rate_limit_window_seconds)
    if backend == "memory":
        return InMemoryRateLimiter(settings.rate_limit_requests, settings.rate_limit_window_seconds)
    raise RuntimeError(f"Unknown RATE_LIMIT_BACKEND: {settings.rate_limit_backend}")


def validate_rate_limit_configuration(settings: Settings) -> None:
    backend = settings.rate_limit_backend.lower()
    if backend == "auto":
        backend = "firestore" if settings.database_mode.lower() == "firestore" else "memory"
    if backend not in {"memory", "firestore"}:
        raise RuntimeError(f"Unknown RATE_LIMIT_BACKEND: {settings.rate_limit_backend}")
    if (
        settings.environment.lower() == "production"
        and backend == "memory"
        and not settings.rate_limit_single_instance
    ):
        raise RuntimeError(
            "The in-memory rate limiter is per-instance. In production use "
            "RATE_LIMIT_BACKEND=firestore, or set RATE_LIMIT_SINGLE_INSTANCE=true "
            "and run exactly one instance."
        )
