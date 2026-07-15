"""
bpc-client — Python implementation of the BPC (Bound Pair Credentials) protocol.

BPC is a request authentication protocol that binds API access to a specific
software pair key, a registered pair identity, and a user-chosen secret. Every request
is individually signed, timestamped, and nonce-protected.

Quick start:
    from bpc_client import BPCClient

    client = BPCClient.register(
        base_url="https://api.example.com",
        name="my-app",
        secret="ValidPairSecret1!@",
    )
    response = client.get("/api/data")

See https://github.com/rblake2320/bpc-protocol for the full spec.
"""

from .client import BPCClient, BPCPair, BPCError, BPCAuthError, BPCPairLockedError
from .crypto import generate_keypair, sign_request, compute_body_hash, derive_secret_hmac
from .runtime_capture import (
    collect_runtime_metadata,
    emit_key_generation_capture,
    sanitize_capture_value,
    set_key_generation_capture_sink,
)

__version__ = "1.0.0"
__all__ = [
    "BPCClient",
    "BPCPair",
    "BPCError",
    "BPCAuthError",
    "BPCPairLockedError",
    "generate_keypair",
    "sign_request",
    "compute_body_hash",
    "derive_secret_hmac",
    "collect_runtime_metadata",
    "emit_key_generation_capture",
    "sanitize_capture_value",
    "set_key_generation_capture_sink",
]
