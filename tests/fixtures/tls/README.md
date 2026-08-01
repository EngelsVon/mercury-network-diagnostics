# Test-only TLS material

`test-ca.pem` is a private certificate authority used only by the controlled
loopback tests. `localhost-cert.pem` and `localhost-key.pem` form a server
certificate chain signed by that CA.

The server certificate contains SANs for `localhost`, `127.0.0.1`, and `::1`.
These files are intentionally committed test fixtures, are excluded from
package data, and must never be used for production listeners or trust stores.
