"""
BPC Nonce Store — tracks consumed nonces to prevent replay attacks.

InMemoryNonceStore is suitable for single-instance development.
For production multi-instance deployments, use a Redis-backed implementation.
"""

import time
from typing import Dict, Protocol


class NonceStore(Protocol):
    def consume(self, nonce: str, ttl_ms: int) -> bool: ...
    """Returns True if nonce was fresh (not seen before), False if replay."""


class InMemoryNonceStore:
    """
    In-memory nonce store with lazy expiry eviction.
    NOT suitable for multi-instance production deployments — use Redis.
    """

    def __init__(self):
        self._nonces: Dict[str, float] = {}  # nonce -> expiry_time (seconds)

    def consume(self, nonce: str, ttl_ms: int = 130_000) -> bool:
        """
        Attempt to consume a nonce.
        Returns True if fresh, False if already seen (replay).
        TTL default: 130,000ms (2 × 60s window + 10s buffer per spec).
        """
        now = time.time()
        self._evict(now)

        if nonce in self._nonces:
            return False  # replay

        expiry = now + (ttl_ms / 1000)
        self._nonces[nonce] = expiry
        return True

    def _evict(self, now: float) -> None:
        """Lazy eviction of expired nonces."""
        expired = [n for n, exp in self._nonces.items() if exp <= now]
        for n in expired:
            del self._nonces[n]

    def size(self) -> int:
        return len(self._nonces)
