"""Mercury test suite."""
"""Test-suite process setup."""

# The available Python installation injects pip's Windows trust-store wrapper
# into ``ssl``.  That wrapper does not present a loaded client certificate to
# an asyncio mTLS server on Python 3.13, so restore CPython's standard context
# for controlled Mercury TLS tests.  This is deliberately test-only; Mercury
# itself uses the host application's SSL configuration unchanged.
try:
    import ssl
    from pip._vendor import truststore

    if ssl.SSLContext.__module__.startswith("pip._vendor.truststore"):
        truststore.extract_from_ssl()
except (ImportError, AttributeError):
    pass
