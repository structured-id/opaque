/**
 * Key schedule tests (RFC 9807 Section 4).
 *
 * Tests: deriveRandomizedPassword, store/recover roundtrip,
 * maskResponse/unmaskResponse roundtrip, envelope serialization,
 * wrong password rejection, createCleartextCredentials.
 */
import { describe, it, expect } from 'vitest';
import {
  deriveRandomizedPassword,
  store,
  recover,
  maskResponse,
  unmaskResponse,
  createCleartextCredentials,
  serializeEnvelope,
  deserializeEnvelope,
  envelopeSize,
} from '../../src/key-schedule.js';
import {
  RISTRETTO255_SHA512,
  P256_SHA256,
  P384_SHA384,
  P521_SHA512,
  type CipherSuite,
} from '../../src/suites.js';
import { getGroup } from '../../src/group/index.js';
import { randomBytes } from '@noble/hashes/utils.js';

const te = new TextEncoder();

const ALL_SUITES: CipherSuite[] = [RISTRETTO255_SHA512, P256_SHA256, P384_SHA384, P521_SHA512];

// Helper: create a deriveKeyPair function for a suite
function makeDeriveKP(suite: CipherSuite) {
  const group = getGroup(suite.curve);
  return (seed: Uint8Array) => {
    const secretKey = group.scalarReduce(seed);
    const publicKey = group.serializeElement(group.scalarBaseMult(secretKey));
    return { secretKey, publicKey };
  };
}

// Helper: generate fake OPRF output for a suite
function fakeOprfOutput(suite: CipherSuite): Uint8Array {
  return randomBytes(suite.oprfOutputSize);
}

describe('deriveRandomizedPassword', () => {
  for (const suite of ALL_SUITES) {
    it(`deterministic for ${suite.name}`, () => {
      const oprfOut = fakeOprfOutput(suite);
      const a = deriveRandomizedPassword(oprfOut, suite);
      const b = deriveRandomizedPassword(oprfOut, suite);
      expect(a).toEqual(b);
    });

    it(`different OPRF outputs → different passwords for ${suite.name}`, () => {
      const a = deriveRandomizedPassword(fakeOprfOutput(suite), suite);
      const b = deriveRandomizedPassword(fakeOprfOutput(suite), suite);
      expect(a).not.toEqual(b);
    });
  }
});

describe('Envelope serialization', () => {
  for (const suite of ALL_SUITES) {
    it(`serialize/deserialize roundtrip for ${suite.name}`, () => {
      const nonce = randomBytes(suite.nonceSize);
      const authTag = randomBytes(suite.macSize);
      const env = { nonce, authTag };

      const serialized = serializeEnvelope(env);
      expect(serialized.length).toBe(envelopeSize(suite));

      const deserialized = deserializeEnvelope(serialized, suite);
      expect(deserialized.nonce).toEqual(nonce);
      expect(deserialized.authTag).toEqual(authTag);
    });
  }

  it('envelopeSize = nonceSize + macSize', () => {
    for (const suite of ALL_SUITES) {
      expect(envelopeSize(suite)).toBe(suite.nonceSize + suite.macSize);
    }
  });
});

describe('createCleartextCredentials', () => {
  it('includes server_public_key, server_identity, client_identity', () => {
    const serverPk = randomBytes(33);
    const clientPk = randomBytes(33);
    const serverId = te.encode('server.example.com');
    const clientId = te.encode('alice@example.com');

    const creds = createCleartextCredentials(serverPk, clientPk, serverId, clientId);

    // Must start with serverPublicKey
    expect(creds.slice(0, 33)).toEqual(serverPk);
    // Must contain I2OSP(len(serverId), 2) followed by serverId
    const serverIdLen = (creds[33]! << 8) | creds[34]!;
    expect(serverIdLen).toBe(serverId.length);
    expect(creds.slice(35, 35 + serverIdLen)).toEqual(serverId);
  });

  it('defaults identity to public key when undefined', () => {
    const serverPk = randomBytes(33);
    const clientPk = randomBytes(33);

    const withExplicit = createCleartextCredentials(serverPk, clientPk, serverPk, clientPk);
    const withDefault = createCleartextCredentials(serverPk, clientPk, undefined, undefined);

    expect(withExplicit).toEqual(withDefault);
  });
});

describe('Store / Recover', () => {
  for (const suite of ALL_SUITES) {
    describe(suite.name, () => {
      it('store/recover roundtrip succeeds', () => {
        const randPw = deriveRandomizedPassword(fakeOprfOutput(suite), suite);
        const group = getGroup(suite.curve);
        const serverKp = group.generateKeypair();
        const deriveKP = makeDeriveKP(suite);
        const serverId = te.encode('server.example.com');
        const clientId = te.encode('alice@example.com');

        const storeResult = store(randPw, serverKp.publicKey, deriveKP, suite, serverId, clientId);
        expect(storeResult.envelope.nonce.length).toBe(suite.nonceSize);
        expect(storeResult.envelope.authTag.length).toBe(suite.macSize);
        expect(storeResult.clientPublicKey.length).toBe(suite.elementSize);
        expect(storeResult.maskingKey.length).toBe(suite.oprfOutputSize);
        expect(storeResult.exportKey.length).toBe(suite.oprfOutputSize);

        const recoverResult = recover(
          randPw,
          serverKp.publicKey,
          storeResult.envelope,
          deriveKP,
          suite,
          serverId,
          clientId,
        );

        expect(recoverResult.clientPublicKey).toEqual(storeResult.clientPublicKey);
        expect(recoverResult.exportKey).toEqual(storeResult.exportKey);
        expect(recoverResult.clientSecretKey.length).toBe(suite.scalarSize);
      });

      it('recover rejects wrong randomized password', () => {
        const correctPw = deriveRandomizedPassword(fakeOprfOutput(suite), suite);
        const wrongPw = deriveRandomizedPassword(fakeOprfOutput(suite), suite);
        const group = getGroup(suite.curve);
        const serverKp = group.generateKeypair();
        const deriveKP = makeDeriveKP(suite);
        const serverId = te.encode('server.example.com');
        const clientId = te.encode('alice@example.com');

        const storeResult = store(
          correctPw,
          serverKp.publicKey,
          deriveKP,
          suite,
          serverId,
          clientId,
        );

        expect(() =>
          recover(
            wrongPw,
            serverKp.publicKey,
            storeResult.envelope,
            deriveKP,
            suite,
            serverId,
            clientId,
          ),
        ).toThrow('Envelope recovery failed');
      });

      it('recover rejects tampered auth tag', () => {
        const randPw = deriveRandomizedPassword(fakeOprfOutput(suite), suite);
        const group = getGroup(suite.curve);
        const serverKp = group.generateKeypair();
        const deriveKP = makeDeriveKP(suite);

        const storeResult = store(randPw, serverKp.publicKey, deriveKP, suite);
        const tamperedTag = new Uint8Array(storeResult.envelope.authTag);
        tamperedTag[0] ^= 0xff;
        const tamperedEnvelope = { nonce: storeResult.envelope.nonce, authTag: tamperedTag };

        expect(() =>
          recover(randPw, serverKp.publicKey, tamperedEnvelope, deriveKP, suite),
        ).toThrow('Envelope recovery failed');
      });
    });
  }
});

describe('maskResponse / unmaskResponse', () => {
  for (const suite of ALL_SUITES) {
    it(`roundtrip for ${suite.name}`, () => {
      const maskingKey = randomBytes(suite.oprfOutputSize);
      const serverPublicKey = getGroup(suite.curve).generateKeypair().publicKey;
      const envelope = {
        nonce: randomBytes(suite.nonceSize),
        authTag: randomBytes(suite.macSize),
      };

      const { maskingNonce, maskedResponse } = maskResponse(
        maskingKey,
        serverPublicKey,
        envelope,
        suite,
      );

      const recovered = unmaskResponse(maskingKey, maskingNonce, maskedResponse, suite);

      expect(recovered.serverPublicKey).toEqual(serverPublicKey);
      expect(recovered.envelope.nonce).toEqual(envelope.nonce);
      expect(recovered.envelope.authTag).toEqual(envelope.authTag);
    });

    it(`wrong masking key fails to unmask for ${suite.name}`, () => {
      const maskingKey1 = randomBytes(suite.oprfOutputSize);
      const maskingKey2 = randomBytes(suite.oprfOutputSize);
      const serverPublicKey = getGroup(suite.curve).generateKeypair().publicKey;
      const envelope = {
        nonce: randomBytes(suite.nonceSize),
        authTag: randomBytes(suite.macSize),
      };

      const { maskingNonce, maskedResponse } = maskResponse(
        maskingKey1,
        serverPublicKey,
        envelope,
        suite,
      );

      const recovered = unmaskResponse(maskingKey2, maskingNonce, maskedResponse, suite);
      // Wrong key → wrong server public key
      expect(recovered.serverPublicKey).not.toEqual(serverPublicKey);
    });
  }
});
