'use strict';
// Small software authenticator for exercising the real server verifier with
// independently generated ES256 keys, CBOR attestation and signed assertions.
const crypto = require('crypto');
const { isoCBOR } = require('@simplewebauthn/server/helpers');
const hash = value => crypto.createHash('sha256').update(value).digest();
const b64 = value => Buffer.from(value).toString('base64url');

function authenticator(algorithm = 'ES256') {
  const rsa = algorithm === 'RS256';
  const { privateKey, publicKey } = rsa
    ? crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    : crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const id = crypto.randomBytes(32);
  const cose = isoCBOR.encode(new Map(rsa ? [
    [1, 3], [3, -257], [-1, Buffer.from(jwk.n, 'base64url')], [-2, Buffer.from(jwk.e, 'base64url')],
  ] : [
    [1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')],
  ]));
  function authData(rpID, flags, counter) {
    const count = Buffer.alloc(4);
    count.writeUInt32BE(counter);
    return Buffer.concat([hash(rpID), Buffer.from([flags]), count]);
  }
  return {
    id: b64(id),
    register(options, overrides = {}) {
      const data = Buffer.from(JSON.stringify({
        type: 'webauthn.create', challenge: options.challenge, origin: 'https://mux.example.com', ...overrides,
      }));
      const len = Buffer.alloc(2); len.writeUInt16BE(id.length);
      const attestation = isoCBOR.encode(new Map([
        ['fmt', 'none'], ['attStmt', new Map()],
        ['authData', Buffer.concat([
          authData(options.rp.id, overrides.uv === false ? 0x41 : 0x45, 0),
          Buffer.alloc(16), len, id, cose,
        ])],
      ]));
      return {
        id: b64(id), rawId: b64(id), type: 'public-key', clientExtensionResults: { credProps: { rk: true } },
        response: { clientDataJSON: b64(data), attestationObject: b64(attestation), transports: ['internal'] },
      };
    },
    login(options, userHandle, overrides = {}) {
      const data = Buffer.from(JSON.stringify({
        type: 'webauthn.get', challenge: options.challenge, origin: 'https://mux.example.com', ...overrides,
      }));
      const auth = authData(overrides.rpID || options.rpId, overrides.uv === false ? 1 : 5, overrides.counter ?? 1);
      const signature = crypto.sign('sha256', Buffer.concat([auth, hash(data)]), privateKey);
      if (overrides.tamper) signature[signature.length - 1] ^= 1;
      return {
        id: b64(id), rawId: b64(id), type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: b64(data), authenticatorData: b64(auth), signature: b64(signature), userHandle },
      };
    },
  };
}
module.exports = { authenticator };
