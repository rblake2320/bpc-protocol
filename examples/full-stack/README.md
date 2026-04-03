# BPC Full-Stack Example

## What this demonstrates

A complete BPC Protocol flow: client registration, signed API requests with replay protection, and server-side verification with anomaly tracking. Both legitimate requests and attack scenarios (replay, unknown pair) are exercised to confirm the protocol rejects invalid traffic.

## How to run

```
npx tsx server.ts
npx tsx client.ts
```

## Expected output

Server terminal:
```
BPC Full-Stack Example Server running on http://localhost:3100
Endpoints:
  POST /bpc/register  — Register a new pair (dev mode: auto-approve)
  GET  /api/status    — Protected: returns server status
  GET  /api/users     — Protected: returns user list

[00:00.000] POST /bpc/register => REGISTERED pair=pair_a1b2c3d4e5f6a7b8
[00:00.001] GET /api/status => PASS pair=pair_a1b2c3d4e5f6a7b8
[00:00.002] GET /api/status => PASS pair=pair_a1b2c3d4e5f6a7b8
[00:00.003] GET /api/status => PASS pair=pair_a1b2c3d4e5f6a7b8
[00:00.004] GET /api/users => PASS pair=pair_a1b2c3d4e5f6a7b8
[00:00.005] GET /api/status => PASS pair=pair_a1b2c3d4e5f6a7b8
[00:00.006] GET /api/status => DENIED (replay_detected)
[00:00.007] GET /api/status => DENIED (unknown_pair)
```

Client terminal:
```
=== BPC Full-Stack End-to-End Test ===

1. Registering new pair...
  [PASS] Registration — pair=pair_a1b2c3d4e5f6a7b8

2. Sending 3 signed requests to /api/status...
  [PASS] GET /api/status (1/3) — status=200
  [PASS] GET /api/status (2/3) — status=200
  [PASS] GET /api/status (3/3) — status=200

3. Sending signed request to /api/users...
  [PASS] GET /api/users — users=["alice","bob","charlie"]

4. Attempting replay attack (reusing old headers)...
  [PASS] Legitimate request (sets nonce) — status=200
  [PASS] Replay attempt — status=401 error=replay_detected

5. Attempting request with unknown pair ID...
  [PASS] Unknown pair ID — status=401 error=unknown_pair

=== End-to-End Test Complete ===
```
