# bpc-client

Python client SDK for the **BPC (Bound Pair Credentials)** pair-key request protocol.

BPC combines an ECDSA P-256 pair key, a secret-derived request HMAC, a fresh nonce, and a timestamp. This software client exports its private key for local persistence; it does not provide hardware binding or attestation.

## Install

```bash
pip install bpc-client
```

## 3-Line Integration

```python
from bpc_client import BPCClient

# Register a new pair (development mode — auto-approved)
client = BPCClient.register(base_url="https://api.example.com", name="my-app", secret="ValidPairSecret1!@")

# Every request is automatically signed
response = client.get("/api/data")
response = client.post("/api/items", json={"name": "test"})
```

## CLI

```bash
bpc pair register --url https://api.example.com --name my-app --secret ValidPairSecret1!@
bpc pair list
bpc status --name my-app
bpc audit --name my-app
bpc request GET /api/data --name my-app
```

## MCP Server (Claude Desktop)

```json
{
  "mcpServers": {
    "bpc": { "command": "bpc-mcp" }
  }
}
```

## Protocol

BPC implements a 12-step server-side verification pipeline:
pair key (ECDSA P-256) + HKDF-derived HMAC verifier + nonce (UUID) + timestamp window + body hash (SHA-256) + closed coarse scope.

See the [full spec](https://github.com/rblake2320/bpc-protocol/blob/main/spec/bpc-spec-v1.md).
