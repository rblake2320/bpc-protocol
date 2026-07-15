# BPC Scope Model

BPC v0.2 uses a closed, coarse authorization enum:

- `read`: `GET`, `HEAD`, `OPTIONS`
- `read-write`: read methods plus `POST`, `PUT`, `PATCH`
- `admin`: all supported methods, including `DELETE`

Namespaced or wildcard values such as `read:*` are deliberately rejected.
Adding prefix or glob matching to the credential layer would make privilege
meaning dependent on string parsing and could silently widen authority.

Fine-grained permissions belong in the governed application's policy engine.
The application first authenticates the BPC pair, then authorizes the concrete
resource and action. A future protocol version may add structured permissions,
but it must use a versioned schema, explicit deny precedence, canonical
normalization, and an adversarial escalation suite. It will not reinterpret the
existing `scope` string.
