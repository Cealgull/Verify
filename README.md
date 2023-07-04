# Cealgull Verify

Cealgull Verify is a simple email verification server that serves verifying identities from a certain organization

by validating their emails through codes. The server performs Two-factor authentication. After validating email,

the server will sign a ring of public keys and dispatch a random private key asking the client to perform an

unlinkable ring signature for anonymous account creation. This cryptographically sets the anonymous account from

the real email which guarantee untraceable registration.
