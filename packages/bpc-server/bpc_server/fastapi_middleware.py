"""
BPC FastAPI Middleware — automatically verifies BPC signatures on all protected routes.

Usage:
    from fastapi import FastAPI
    from bpc_server import BPCFastAPIMiddleware, InMemoryPairRegistry

    app = FastAPI()
    registry = InMemoryPairRegistry()
    app.add_middleware(
        BPCFastAPIMiddleware,
        registry=registry,
        exclude_paths=["/bpc/register", "/bpc/health", "/docs", "/openapi.json"],
    )

    @app.get("/api/data")
    async def get_data(request: Request):
        pair = request.state.bpc_pair  # BPCVerificationResult available
        return {"pair_id": pair.pair_id}
"""

from typing import List, Optional

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    HAS_STARLETTE = True
except ImportError:
    HAS_STARLETTE = False

from .verifier import BPCVerifier
from .registry import InMemoryPairRegistry
from .nonce_store import InMemoryNonceStore


if HAS_STARLETTE:
    class BPCFastAPIMiddleware(BaseHTTPMiddleware):
        def __init__(
            self,
            app,
            registry=None,
            nonce_store=None,
            sig_window_ms: int = 60_000,
            lockout_count: int = 10,
            exclude_paths: Optional[List[str]] = None,
        ):
            super().__init__(app)
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
                "/docs",
                "/openapi.json",
                "/redoc",
            ])

        async def dispatch(self, request: Request, call_next):
            path = request.url.path

            # Skip excluded paths
            if path in self.exclude_paths:
                return await call_next(request)

            body = await request.body()
            result = self.verifier.verify(
                headers=dict(request.headers),
                method=request.method,
                path=path,
                body=body,
            )

            if not result.ok:
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": {
                            "code": result.error_code,
                            "message": result.error_message,
                        }
                    },
                )

            request.state.bpc_pair = result
            request.state.bpc_pair_id = result.pair_id
            return await call_next(request)

else:
    class BPCFastAPIMiddleware:  # type: ignore
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "FastAPI/Starlette is required for BPCFastAPIMiddleware. "
                "Install with: pip install bpc-server[fastapi]"
            )
