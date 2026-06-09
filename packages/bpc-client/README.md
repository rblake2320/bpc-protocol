# bpc-client

Python client SDK for the **BPC (Bound Pair Credentials)** protocol — cryptographic device-binding and per-request signing for APIs.

BPC replaces static API keys with a multi-factor, per-request signing protocol. Every request is signed with an ECDSA P-256 device key, a user-chosen secret (HMAC-derived), a fresh nonce, and a timestamp. Stolen credentials are useless without the device key.

## Install

```bash
pip install bpc-client
```

## 3-Line Integration

```python
from bpc_client import BPCClient

# Register a new pair (development mode — auto-approved)
client = BPCClient.register(base_url="https://api.example.com", name="my-app", secret="MySecret1!")

# Every request is automatically signed
response = client.get("/api/data")
response = client.post("/api/items", json={"name": "test"})
```

## CLI

```bash
bpc pair register --url https://api.example.com --name my-app --secret MySecret1!
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
device key (ECDSA P-256) + secret (HMAC-SHA-256) + nonce (UUID) + timestamp (60s window) + body hash (SHA-256) + scope enforcement.

See the [full spec](https://github.com/rblake2320/bpc-protocol/blob/main/spec/bpc-spec-v1.md).
