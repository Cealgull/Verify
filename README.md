# Cealgull Verify

![Unittests](https://github.com/Cealgull/Verify/actions/workflows/go.yml/badge.svg)
[![codecov](https://codecov.io/gh/Cealgull/Verify/branch/main/graph/badge.svg?token=JK8ZJ4VM79)](https://codecov.io/gh/Cealgull/Verify)

Cealgull Verify is a simple email verification server that serves verifying identities from a certain organization by validating their emails through codes. The server performs Two-factor authentication. After validating email, the server will sign a ring of public keys and dispatch a random private key asking the client to perform an unlinkable ring signature for anonymous account creation. This cryptographically sets the anonymous account from the real email which guarantee untraceable registration.
