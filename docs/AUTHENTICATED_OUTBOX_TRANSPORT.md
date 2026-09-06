# Authenticated durable-outbox transport

`HttpOutboxTransport` and `createHttpOutboxReceiver` provide the authenticated
network hop between a durable BPC source publisher and receiver. The request
MAC uses length-prefixed framing over the domain, key identifier, method, exact
path, timestamp, nonce, and SHA-256 of the raw body. The receiver checks the
exact path and media type, bounds the raw body, verifies freshness and the MAC,
and consumes a durable single-use nonce before parsing or applying the record.

The response is bound to the individual request attempt. Its MAC covers the
fresh request nonce, request-body digest, path, and canonical receiver receipt.
The source also verifies the receiver's decision-bound receipt before its
durable publisher may acknowledge a row. Multiple request and response key
identifiers can overlap during governed rotation.

`PgReplayNonceStore.open()` pins a configured PostgreSQL schema, requires a
`SERIALIZABLE` transaction, and attests the replay table's columns, indexes,
constraints, triggers, policies, persistence, and RLS posture. Every nonce
consumption repeats that attestation in the same transaction as DB-clock expiry,
pruning, and atomic insertion. A table lock is acquired before catalog
attestation and held through the nonce write, so concurrent DDL cannot replace
or weaken the replay authority between inspection and use. Receiver composition rejects non-attested stores
and a retention horizon that cannot cover the full freshness window,
worst-case clock skew, and a safety margin.

The publisher consumes the transport's closed error taxonomy: network, timeout,
and verifier-unavailability failures remain unacknowledged for retry; terminal
authentication/protocol failures are durably quarantined instead of retried
forever. The earliest unacknowledged row remains the ordering authority even
when quarantined, so a terminal row durably halts later delivery across
publisher restarts until governed recovery resolves the stream.

## Evidence and boundary

The two-PostgreSQL drill now crosses a real loopback HTTP socket between
distinct PostgreSQL cluster identities. It injects response loss after receiver
commit, closes the receiver pool, reopens the same durable receiver authority,
and proves ordered convergence, one apply per operation, zero missing
acknowledged rows, and measured convergence time. It also exercises durable
raw-request replay rejection after store reconstruction, a conflicting DDL
lock, same-count-but-wrong index drift, and terminal-quarantine persistence
across publisher reconstruction.

This is authenticated same-host network and independent-state mechanism
evidence. It does not prove independent physical failure domains, external
promotion fencing, split-brain behavior, snapshot-and-tail resynchronization,
or availability across a real network partition. Issue #16 remains open for
those gates.
