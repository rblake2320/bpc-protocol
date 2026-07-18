# Durable Pair Authority

`PgTransactionalPairStore` couples each PostgreSQL pair-authority mutation to
the durable outbox in one `SERIALIZABLE` transaction. Admission, fencing,
sequence allocation, outbox insertion, and the authoritative table change all
commit or all roll back.

## Confidential Replication

`secretHash` is an operational HMAC key. It is never placed in cleartext in an
outbox record. Pair and pending-registration set operations carry an
AES-256-GCM payload with a fresh 96-bit nonce. The authenticated additional data
binds the protocol domain/version, stream, mutation kind, pair or pending
identity, algorithm, and key identifier. A key identifier supports rotation;
the key resolver must return a 32-byte key from local protected key custody.
Network/KMS calls are not permitted while the receiver transaction is open.

The receiver authenticates and opens the payload before changing authority.
An unavailable or wrong key, altered tag, changed identity, invalid public JWK,
or malformed payload aborts the receiver transaction, including its applied
history and checkpoint update.

## Schema Readiness

Schema version 3 attests the outbox tables and both pair-authority tables as one
catalog. Constructors require a transactor-and-schema-bound readiness token.
The legacy `PG_SCHEMA` export uses the governed pair-table DDL after a
fresh-only preflight; it is not a migration or combined-v3 readiness gate.

Existing standalone version-2 installations first call
`prepareLegacyPairAuthorityV2ForMigration`, which requires exactly the two
legacy authority tables and no pre-existing HA/outbox objects. It locks those
tables, checks their relation posture, creates only the missing outbox
infrastructure, and stamps the v2 authority without changing pair data. The
operator then calls `migrateLegacyPairAuthorityToV3` in the same maintenance
window. Both operations fail closed if the transactor cannot acquire authority
locks before its serializable snapshot.

The migration is an offline maintenance operation: application writers must be
quiesced and the migration identity must own the tables. It takes access-
exclusive locks before its first snapshot/catalog/data read, rebuilds both
authority tables, validates copied rows under
the v3 constraints, attests the complete combined schema, and advances the
version marker in the same transaction. Invalid data, unexpected columns,
staging collisions, or catalog drift roll the entire migration back.

## Boundaries

This is single-node mechanism evidence, not high-availability evidence. Issue
#16 remains open for snapshot/tail resynchronization, promotion eligibility, a
real two-node PostgreSQL and Redis failover/split-brain drill, and measured
RPO/RTO. Registry-level compound approval and compare-and-set lifecycle updates
are separate work and must not be inferred from this store mechanism.
