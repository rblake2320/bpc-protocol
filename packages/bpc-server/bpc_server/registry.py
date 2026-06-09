"""
BPC Pair Registry — stores and manages registered pairs.

InMemoryPairRegistry is suitable for development and testing.
For production, implement the PairRegistry protocol with PostgreSQL or Redis.
"""

import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Protocol


@dataclass
class PairRecord:
    pair_id: str
    name: str
    scope: str          # "read" | "read-write" | "admin"
    mode: str           # "development" | "production"
    public_key_jwk: dict
    secret_hash: str    # Argon2id hash of the user secret
    status: str = "active"  # "active" | "revoked" | "pending"
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    failed_sigs: int = 0
    lockout_count: int = 10


class PairRegistry(Protocol):
    def get(self, pair_id: str) -> Optional[PairRecord]: ...
    def register(self, record: PairRecord) -> None: ...
    def revoke(self, pair_id: str) -> None: ...
    def increment_failed_sigs(self, pair_id: str) -> None: ...
    def reset_failed_sigs(self, pair_id: str) -> None: ...


class InMemoryPairRegistry:
    """Thread-safe in-memory pair registry. Use for development and testing."""

    def __init__(self):
        self._pairs: Dict[str, PairRecord] = {}

    def get(self, pair_id: str) -> Optional[PairRecord]:
        return self._pairs.get(pair_id)

    def register(self, record: PairRecord) -> None:
        self._pairs[record.pair_id] = record

    def revoke(self, pair_id: str) -> None:
        if pair_id in self._pairs:
            self._pairs[pair_id].status = "revoked"

    def increment_failed_sigs(self, pair_id: str) -> None:
        if pair_id in self._pairs:
            self._pairs[pair_id].failed_sigs += 1

    def reset_failed_sigs(self, pair_id: str) -> None:
        if pair_id in self._pairs:
            self._pairs[pair_id].failed_sigs = 0

    def all_pairs(self) -> list:
        return list(self._pairs.values())
