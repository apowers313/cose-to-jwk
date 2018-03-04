This was created to convert [CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152) to [JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517). I specifically needed this for [WebAuthn](https://www.w3.org/TR/webauthn/) and I'm using it with [jwk-to-pem](https://www.npmjs.com/package/jwk-to-pem) to create PEM strings that work with [Node.js's Crypto library](https://nodejs.org/api/crypto.html).

Notes:
* This currently only supports ECDSA and RSA. GitHub pull requests or issues for other crypto suites are welcome.
* This doesn't do any other COSE things (signing, decrypting, etc.)
* This could probably use more testing (although it's not very sophisticated)