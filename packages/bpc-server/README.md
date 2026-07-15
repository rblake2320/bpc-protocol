# bpc-server

Python server-side middleware for the **BPC (Bound Pair Credentials)** protocol. Verifies BPC-signed requests in FastAPI and Flask applications using the full 12-step pipeline from the BPC spec v1.0.

## Install

```bash
pip install bpc-server[fastapi]   # FastAPI + Starlette
pip install bpc-server[flask]     # Flask
pip install bpc-server[all]       # Both
```

## FastAPI

```python
from fastapi import FastAPI, Request
from bpc_server import BPCFastAPIMiddleware, InMemoryPairRegistry, PairRecord

app = FastAPI()
registry = InMemoryPairRegistry()

# Register a pair (in production, load from your database)
registry.register(PairRecord(
    pair_id="pair_abc123",
    name="my-agent",
    scope="read-write",
    mode="development",
    public_key_jwk={...},  # from bpc-client registration
    secret_hash="base64url_hkdf_request_hmac_key",
))

app.add_middleware(BPCFastAPIMiddleware, registry=registry)

@app.get("/api/data")
async def get_data(request: Request):
    pair = request.state.bpc_pair  # BPCVerificationResult
    return {"pair_id": pair.pair_id, "scope": pair.pair.scope}
```

## Flask

```python
from flask import Flask, g
from bpc_server import BPCFlaskMiddleware, InMemoryPairRegistry

app = Flask(__name__)
registry = InMemoryPairRegistry()
BPCFlaskMiddleware(app, registry=registry)

@app.route("/api/data")
def get_data():
    return {"pair_id": g.bpc_pair_id}
```

## Standalone Verifier

```python
from bpc_server import BPCVerifier, InMemoryPairRegistry, InMemoryNonceStore

verifier = BPCVerifier(registry=registry, nonce_store=InMemoryNonceStore())
result = verifier.verify(headers=request.headers, method="GET", path="/api/data")
if not result.ok:
    return 401, result.error_code
```

## 12-Step Verification Pipeline

1. Headers present (`X-BPC-Pair-ID`, `X-BPC-Signature`, `X-BPC-Signed-Data`, `X-BPC-Version`)
2. Pair exists and is active (not revoked, not expired)
3. Pair not locked out
4. Decode and parse canonical payload
5. Protocol version check (`"1.0"`)
6. Timestamp within ±60s window
7. Secret-derived HMAC and timestamp valid
8. Method, path, pair ID, and body hash match payload
9. ECDSA-SHA-256 signature valid
10. Scope enforcement (`read` / `read-write` / `admin`)
11. Atomically consume the nonce after all other checks pass

See the [full spec](https://github.com/rblake2320/bpc-protocol/blob/main/spec/bpc-spec-v1.md).
