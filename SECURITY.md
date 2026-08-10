# Security policy

Please report suspected vulnerabilities privately through System Locker's
official support channel. Do not include credentials, private keys, live
session tokens, or customer data in a public issue.

## Client trust boundary

The application developer is responsible for embedding the correct public
Ed25519 key through a trusted release channel. This library never fetches a
replacement trust root from an authentication response.

Every loss of signature validity, challenge binding, system binding, protocol
binding, or freshness is treated as an authentication failure. Unsigned JSON
is never authorization. The one protocol-defined
exception is an unsigned `SIGNING_KEY_REVOKED` heartbeat response when a
session's pinned database key row was deleted; this exception can only end an
existing session and cannot grant access.

## Credential handling

Credentials are used for initialization and are not stored by `Client`.
Temporary request buffers are overwritten on a best-effort basis after use.
The operating system, allocator, HTTP library, debugger, crash reporter, or a
fully compromised process may still retain or observe copies.
