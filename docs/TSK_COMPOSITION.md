# BPC + TSK production composition

BPC and TSK are independent verifiers. A production request is authorized only
when both verifiers accept a fresh request **and** resolve to the same principal.
Do not treat a successful BPC pair or a successful TSK tumbler credential alone
as authorization for the composed product.

## Supported bridge

The supported composition is `@tsk/bpc-bridge`, not a second bridge in this
repository. It declares `@bpc/server` `^0.2.0` as a peer dependency and exposes
`verifyUltraRequest`. The reviewed TSK checkout contains
`bpc-compatibility-suite.mts`, which runs a valid BPC+TSK request, checks BPC
replay rejection occurs before TSK consumption, and propagates BPC's closed
scope.

Run the compatibility suite from the reviewed TSK checkout, pointing it at this
checkout:

```powershell
$env:BPC_PROTOCOL_PATH = 'C:\path\to\bpc-protocol'
npm run test:bpc-compat
```

## Required request order

1. Canonicalize the real HTTP body and construct `BPCRequestData` from exactly
   the received BPC headers, method, path, body hash, and trusted source IP.
2. Call BPC verification for every request. Treat any `ok: false` result as a
   hard deny. Do not cache a prior successful BPC result as authorization.
3. Pass that fresh BPC verifier closure, the raw single-valued TSK headers, and
   an identity resolver to `verifyUltraRequest`.
4. The resolver must map the authenticated BPC `pairId` to exactly one active
   TSK `clientId`; no wildcard, display-name, or caller-supplied mapping is
   permitted.
5. Authorize the application only when the composed result is `ok: true`; apply
   the closed BPC scope to application authorization separately.

## Production gates

- Use a shared durable BPC nonce backend and durable TSK store before running
  multiple verifier instances.
- Put pair-to-TSK identity bindings in a durable, access-controlled store and
  revoke both sides together when a principal is removed.
- Reject duplicate BPC and TSK headers at the HTTP adapter before either
  verifier sees them.
- Persist audit/checkpoint anchors outside the verifier process. In-memory
  factories are for development and tests only.
- Pin and test a reviewed BPC/TSK version pair in CI. A compatible semver range
  is not deployment evidence.

This contract intentionally does not copy TSK secret material into BPC, or BPC
private key material into TSK.
