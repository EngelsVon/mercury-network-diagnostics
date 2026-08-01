# Test-only TLS material

`test-ca.pem` is a private certificate authority used only by the controlled
loopback tests. `localhost-cert.pem` and `localhost-key.pem` form a server
certificate chain signed by that CA. `peer-client-cert.pem` and
`peer-client-key.pem` are a separate static client-authentication pair signed
by the same CA; their subject is `mercury-test-peer-client` and the client
certificate has the client-auth extended-key-usage.

The server certificate contains SANs for `localhost`, `127.0.0.1`, and `::1`.
These files are intentionally committed test fixtures, are excluded from
package data, and must never be used for production listeners, client
credentials, or trust stores. They are generated once for the repository, not
during test execution.
