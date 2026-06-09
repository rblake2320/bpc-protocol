"""
bpc-server — Python server-side middleware for BPC (Bound Pair Credentials) verification.

Provides:
- FastAPI middleware: BPCFastAPIMiddleware
- Flask middleware: BPCFlaskMiddleware
- Standalone verifier: BPCVerifier (framework-agnostic)
- In-memory pair registry and nonce store (production: use Redis + PostgreSQL)

Quick start (FastAPI):
    from fastapi import FastAPI
    from bpc_server import BPCFastAPIMiddleware, InMemoryPairRegistry

    app = FastAPI()
    registry = InMemoryPairRegistry()
    app.add_middleware(BPCFastAPIMiddleware, registry=registry)

Quick start (Flask):
    from flask import Flask
    from bpc_server import BPCFlaskMiddleware, InMemoryPairRegistry

    app = Flask(__name__)
    registry = InMemoryPairRegistry()
    BPCFlaskMiddleware(app, registry=registry)
"""

from .verifier import BPCVerifier, BPCVerificationResult
from .registry import InMemoryPairRegistry, PairRecord
from .nonce_store import InMemoryNonceStore
from .fastapi_middleware import BPCFastAPIMiddleware
from .flask_middleware import BPCFlaskMiddleware

__version__ = "1.0.0"
__all__ = [
    "BPCVerifier",
    "BPCVerificationResult",
    "InMemoryPairRegistry",
    "PairRecord",
    "InMemoryNonceStore",
    "BPCFastAPIMiddleware",
    "BPCFlaskMiddleware",
]
