# OCM signature test keys

Public **test** keypair for the signature-verification tests. NOT a secret:
it exists only to sign the synthetic `signed-descriptor.json` fixture so the
verifier has a deterministic, checkable input. Never used for anything real.

- `test-rsa.pub.pem` — SPKI public key, imported by the verifier.
- `test-rsa.key.pem` — matching private key, used once to produce the fixture
  via the `ocm` CLI (`ocm sign cv`, RSASSA-PSS, jsonNormalisation/v4alpha1).

The signature in `signed-descriptor.json` was produced by the real `ocm` CLI
(v0.9.0), which is why it pins the exact normalisation and the
maximum-salt-length PSS convention the verifier must match. RSASSA-PSS is
randomised at signing time, so the fixture is frozen, not regenerated in CI.
