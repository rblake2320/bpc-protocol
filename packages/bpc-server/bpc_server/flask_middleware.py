"""
BPC Flask Middleware — verifies BPC signatures on all protected routes.

Usage:
    from flask import Flask, g
    from bpc_server import BPCFlaskMiddleware, InMemoryPairRegistry

    app = Flask(__name__)
    registry = InMemoryPairRegistry()
    BPCFlaskMiddleware(app, registry=registry)

    @app.route("/api/data")
    def get_data():
        pair = g.bpc_pair  # BPCVerificationResult available
        return {"pair_id": pair.pair_id}
"""

from typing import List, Optional

try:
    from flask import Flask, request, jsonify, g
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

from .verifier import BPCVerifier
from .registry import InMemoryPairRegistry
from .nonce_store import InMemoryNonceStore


if HAS_FLASK:
    class BPCFlaskMiddleware:
        def __init__(
            self,
            app: "Flask",
            registry=None,
            nonce_store=None,
            sig_window_ms: int = 60_000,
            lockout_count: int = 10,
            exclude_paths: Optional[List[str]] = None,
        ):
            self.verifier = BPCVerifier(
                registry=registry or InMemoryPairRegistry(),
                nonce_store=nonce_store or InMemoryNonceStore(),
                sig_window_ms=sig_window_ms,
                lockout_count=lockout_count,
            )
            self.exclude_paths = set(exclude_paths or [
                "/bpc/register",
                "/bpc/health",
                "/bpc/approve",
            ])
            app.before_request(self._before_request)

        def _before_request(self):
            path = request.path
            if path in self.exclude_paths:
                return None

            body = request.get_data()
            result = self.verifier.verify(
                headers=dict(request.headers),
                method=request.method,
                path=path,
                body=body,
            )

            if not result.ok:
                return jsonify({
                    "error": {
                        "code": result.error_code,
                        "message": result.error_message,
                    }
                }), 401

            g.bpc_pair = result
            g.bpc_pair_id = result.pair_id
            return None

else:
    class BPCFlaskMiddleware:  # type: ignore
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "Flask is required for BPCFlaskMiddleware. "
                "Install with: pip install bpc-server[flask]"
            )
