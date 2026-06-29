/**
 * AKE tests (RFC 9807 Section 6).
 *
 * Tests: 3DH key agreement, KE serialization, server/client MAC verification,
 * session key agreement, wrong MAC rejection.
 */
import { describe, it, expect } from 'vitest';
import {
  clientAkeStart,
  clientAkeFinish,
  serverAkeRespond,
  serverAkeFinish,
  serializeKE1,
  serializeKE2,
  deserializeKE2,
} from '../../src/ake.js';
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

describe('KE serialization', () => {
  for (const suite of ALL_SUITES) {
    it(`KE1 serialize/roundtrip for ${suite.name}`, () => {
      const credentialRequest = randomBytes(suite.elementSize);
      const { ke1, state } = clientAkeStart(credentialRequest, suite);

      expect(ke1.credentialRequest).toEqual(credentialRequest);
      expect(ke1.clientNonce.length).toBe(suite.nonceSize);
      expect(ke1.clientPublicKeyshare.length).toBe(suite.elementSize);

      const serialized = serializeKE1(ke1);
      expect(serialized.length).toBe(suite.elementSize + suite.nonceSize + suite.elementSize);

      expect(state.clientSecretKeyshare.length).toBeGreaterThan(0);
      expect(state.ke1Serialized).toEqual(serialized);
    });

    it(`KE2 serialize/deserialize roundtrip for ${suite.name}`, () => {
      // credential_response = evaluated_message(Noe) + masking_nonce(Nn) + masked_response(Npk + Nn + Nm)
      const credRespLen =
        suite.elementSize + suite.nonceSize + (suite.elementSize + suite.nonceSize + suite.macSize);
      const credentialResponse = randomBytes(credRespLen);
      const serverNonce = randomBytes(suite.nonceSize);
      const serverPublicKeyshare = getGroup(suite.curve).generateKeypair().publicKey;
      const serverMac = randomBytes(suite.macSize);

      const ke2 = { credentialResponse, serverNonce, serverPublicKeyshare, serverMac };
      const serialized = serializeKE2(ke2);
      const deserialized = deserializeKE2(serialized, suite);

      expect(deserialized.credentialResponse).toEqual(credentialResponse);
      expect(deserialized.serverNonce).toEqual(serverNonce);
      expect(deserialized.serverPublicKeyshare).toEqual(serverPublicKeyshare);
      expect(deserialized.serverMac).toEqual(serverMac);
    });
  }
});

describe('3DH AKE key agreement', () => {
  for (const suite of ALL_SUITES) {
    describe(suite.name, () => {
      it('client and server derive the same session key', () => {
        const group = getGroup(suite.curve);
        const clientKp = group.generateKeypair();
        const serverKp = group.generateKeypair();
        const clientId = te.encode('alice@example.com');
        const serverId = te.encode('server.example.com');
        const credentialRequest = randomBytes(suite.elementSize);
        const credentialResponse = randomBytes(
          suite.elementSize +
            suite.nonceSize +
            (suite.elementSize + suite.nonceSize + suite.macSize),
        );

        // Client starts AKE
        const { ke1, state: clientState } = clientAkeStart(credentialRequest, suite);

        // Server responds
        const { ke2, state: serverState } = serverAkeRespond(
          serverKp.secretKey,
          serverKp.publicKey,
          clientKp.publicKey,
          credentialResponse,
          ke1,
          clientId,
          serverId,
          suite,
        );

        // Client finishes AKE
        const { ke3, sessionKey: clientSessionKey } = clientAkeFinish(
          clientKp.secretKey,
          serverKp.publicKey,
          ke2,
          clientState,
          clientId,
          serverId,
          suite,
        );

        // Server finishes AKE
        const serverSessionKey = serverAkeFinish(ke3, serverState);

        // Both should have the same session key
        expect(clientSessionKey).toEqual(serverSessionKey);
        expect(clientSessionKey.length).toBe(suite.oprfOutputSize);
      });

      it('produces fresh session keys each run', () => {
        const group = getGroup(suite.curve);
        const clientKp = group.generateKeypair();
        const serverKp = group.generateKeypair();
        const clientId = te.encode('alice@example.com');
        const serverId = te.encode('server.example.com');
        const credReq = randomBytes(suite.elementSize);
        const credResp = randomBytes(
          suite.elementSize +
            suite.nonceSize +
            (suite.elementSize + suite.nonceSize + suite.macSize),
        );

        // Run 1
        const { ke1: ke1a, state: csA } = clientAkeStart(credReq, suite);
        const { ke2: ke2a, state: _ssA } = serverAkeRespond(
          serverKp.secretKey,
          serverKp.publicKey,
          clientKp.publicKey,
          credResp,
          ke1a,
          clientId,
          serverId,
          suite,
        );
        const { sessionKey: skA } = clientAkeFinish(
          clientKp.secretKey,
          serverKp.publicKey,
          ke2a,
          csA,
          clientId,
          serverId,
          suite,
        );

        // Run 2
        const { ke1: ke1b, state: csB } = clientAkeStart(credReq, suite);
        const { ke2: ke2b } = serverAkeRespond(
          serverKp.secretKey,
          serverKp.publicKey,
          clientKp.publicKey,
          credResp,
          ke1b,
          clientId,
          serverId,
          suite,
        );
        const { sessionKey: skB } = clientAkeFinish(
          clientKp.secretKey,
          serverKp.publicKey,
          ke2b,
          csB,
          clientId,
          serverId,
          suite,
        );

        // Different ephemeral keys → different session keys
        expect(skA).not.toEqual(skB);
      });

      it('rejects tampered server MAC', () => {
        const group = getGroup(suite.curve);
        const clientKp = group.generateKeypair();
        const serverKp = group.generateKeypair();
        const clientId = te.encode('alice@example.com');
        const serverId = te.encode('server.example.com');
        const credReq = randomBytes(suite.elementSize);
        const credResp = randomBytes(
          suite.elementSize +
            suite.nonceSize +
            (suite.elementSize + suite.nonceSize + suite.macSize),
        );

        const { ke1, state: clientState } = clientAkeStart(credReq, suite);
        const { ke2 } = serverAkeRespond(
          serverKp.secretKey,
          serverKp.publicKey,
          clientKp.publicKey,
          credResp,
          ke1,
          clientId,
          serverId,
          suite,
        );

        // Tamper server MAC
        const tamperedMac = new Uint8Array(ke2.serverMac);
        tamperedMac[0] ^= 0xff;
        const tamperedKE2 = { ...ke2, serverMac: tamperedMac };

        expect(() =>
          clientAkeFinish(
            clientKp.secretKey,
            serverKp.publicKey,
            tamperedKE2,
            clientState,
            clientId,
            serverId,
            suite,
          ),
        ).toThrow('invalid server MAC');
      });

      it('rejects tampered client MAC (KE3)', () => {
        const group = getGroup(suite.curve);
        const clientKp = group.generateKeypair();
        const serverKp = group.generateKeypair();
        const clientId = te.encode('alice@example.com');
        const serverId = te.encode('server.example.com');
        const credReq = randomBytes(suite.elementSize);
        const credResp = randomBytes(
          suite.elementSize +
            suite.nonceSize +
            (suite.elementSize + suite.nonceSize + suite.macSize),
        );

        const { ke1, state: clientState } = clientAkeStart(credReq, suite);
        const { ke2, state: serverState } = serverAkeRespond(
          serverKp.secretKey,
          serverKp.publicKey,
          clientKp.publicKey,
          credResp,
          ke1,
          clientId,
          serverId,
          suite,
        );

        const { ke3 } = clientAkeFinish(
          clientKp.secretKey,
          serverKp.publicKey,
          ke2,
          clientState,
          clientId,
          serverId,
          suite,
        );

        // Tamper client MAC
        const tamperedKE3 = new Uint8Array(ke3);
        tamperedKE3[0] ^= 0xff;

        expect(() => serverAkeFinish(tamperedKE3, serverState)).toThrow('invalid client MAC');
      });
    });
  }
});
