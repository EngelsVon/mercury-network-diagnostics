## Summary

Describe the user-visible change and the evidence semantics it affects.

## Verification

- [ ] `python -m unittest discover -s tests -v`
- [ ] `python -m compileall -q src tests`
- [ ] CLI or Web behavior was checked where applicable

## Safety and compatibility

- [ ] Active targets remain restricted to admitted private scope.
- [ ] Silence, timeout, refusal, response, unsupported, permission, and error remain distinct.
- [ ] Peer mTLS/token/pinning and immutable ceilings are preserved.
- [ ] No credentials, tokens, private keys, certificates, or sensitive test data are included.
- [ ] English and Chinese documentation were updated together when behavior changed.
