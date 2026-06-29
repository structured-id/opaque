/**
 * Integration tests: full OPAQUE registration + login flows.
 *
 * Simulates both client and server sides for all 5 cipher suites.
 * Verifies: session key agreement, export key consistency,
 * wrong password rejection, cross-suite isolation.
 */
import { describe, it, expect } from 'vitest';
import {
  RISTRETTO255_SHA512,
  P256_SHA256,
  P384_SHA384,
  P521_SHA512,
  type CipherSuite,
} from '../../src/suites.js';
import { getGroup } from '../../src/group/index.js';
import { oprfBlind, oprfBlindEvaluate, oprfFinalize, oprfGenerateKeyPair } from '../../src/oprf.js';
import {
  deriveRandomizedPassword,
  store,
  recover,
  maskResponse,
  unmaskResponse,
} from '../../src/key-schedule.js';
import {
  clientAkeStart,
  clientAkeFinish,
  serverAkeRespond,
  serverAkeFinish,
  serializeKE1,
} from '../../src/ake.js';
import { expand } from '@noble/hashes/hkdf.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';

const te = new TextEncoder();

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getHashFn(hash: string): any {
  switch (hash) {
    case 'SHA-256':
      return sha256;
    case 'SHA-384':
      return sha384;
    case 'SHA-512':
      return sha512;
  }
}

const ALL_SUITES: CipherSuite[] = [RISTRETTO255_SHA512, P256_SHA256, P384_SHA384, P521_SHA512];

/**
 * Full OPAQUE flow simulating both client and server.
 *
 * Registration: client → blind → server evaluate → client finalize → record
 * Login: client → KE1 → server KE2 → client KE3 → server finish
 */
function fullOpaqueFlow(suite: CipherSuite, password: string, serverId: string, clientId: string) {
  const group = getGroup(suite.curve);
  const hashFn = getHashFn(suite.hash);
  const serverIdBytes = te.encode(serverId);
  const clientIdBytes = te.encode(clientId);
  const deriveKP = (seed: Uint8Array) => {
    const secretKey = group.scalarReduce(seed);
    const publicKey = group.serializeElement(group.scalarBaseMult(secretKey));
    return { secretKey, publicKey };
  };

  // ── Server setup ──
  const oprfKp = oprfGenerateKeyPair(suite.curve);
  const serverKp = group.generateKeypair();

  // ══════════════════════
  // REGISTRATION PHASE
  // ══════════════════════

  // Client → registrationStart
  const input = te.encode(password);
  const { blind: regBlind, blindedElement: regBlinded } = oprfBlind(suite.curve, input);

  // Server → evaluate OPRF
  const regEvaluated = oprfBlindEvaluate(suite.curve, oprfKp.secretKey, regBlinded);

  // Server → build registration response: evaluated_message || server_public_key
  const regResponse = new Uint8Array(suite.elementSize * 2);
  regResponse.set(regEvaluated, 0);
  regResponse.set(serverKp.publicKey, suite.elementSize);

  // Client → registrationFinish
  const oprfOutput = oprfFinalize(suite.curve, input, regBlind, regEvaluated);
  const randomizedPassword = deriveRandomizedPassword(oprfOutput, suite);
  const storeResult = store(
    randomizedPassword,
    serverKp.publicKey,
    deriveKP,
    suite,
    serverIdBytes,
    clientIdBytes,
  );

  // Registration record (stored on server): clientPublicKey, maskingKey, envelope
  const clientPublicKey = storeResult.clientPublicKey;
  const maskingKey = storeResult.maskingKey;
  const envelope = storeResult.envelope;
  const registrationExportKey = storeResult.exportKey;

  // ══════════════════════
  // LOGIN PHASE
  // ══════════════════════

  // Client → loginStart
  const { blind: loginBlind, blindedElement: loginBlinded } = oprfBlind(suite.curve, input);
  const { ke1, state: clientAkeState } = clientAkeStart(loginBlinded, suite);
  const ke1Bytes = serializeKE1(ke1);

  // Server → evaluate OPRF
  const loginEvaluated = oprfBlindEvaluate(suite.curve, oprfKp.secretKey, loginBlinded);

  // Server → build credential response: evaluated || masking_nonce || masked_response
  const { maskingNonce, maskedResponse } = maskResponse(
    maskingKey,
    serverKp.publicKey,
    envelope,
    suite,
  );
  const credentialResponse = new Uint8Array(
    suite.elementSize + suite.nonceSize + maskedResponse.length,
  );
  credentialResponse.set(loginEvaluated, 0);
  credentialResponse.set(maskingNonce, suite.elementSize);
  credentialResponse.set(maskedResponse, suite.elementSize + suite.nonceSize);

  // Server → AKE respond (KE2)
  const { ke2, state: serverAkeState } = serverAkeRespond(
    serverKp.secretKey,
    serverKp.publicKey,
    clientPublicKey,
    credentialResponse,
    ke1,
    clientIdBytes,
    serverIdBytes,
    suite,
  );

  // Client → loginFinish: unmask, recover, AKE finish
  const loginOprfOutput = oprfFinalize(suite.curve, input, loginBlind, loginEvaluated);
  const loginRandomizedPassword = deriveRandomizedPassword(loginOprfOutput, suite);
  const loginMaskingKey = expand(
    hashFn,
    loginRandomizedPassword,
    te.encode('MaskingKey'),
    suite.oprfOutputSize,
  );

  // Extract credential response from KE2
  const credRespFromKE2 = ke2.credentialResponse;
  const _evalMsg = credRespFromKE2.slice(0, suite.elementSize);
  const mNonce = credRespFromKE2.slice(suite.elementSize, suite.elementSize + suite.nonceSize);
  const mResp = credRespFromKE2.slice(suite.elementSize + suite.nonceSize);

  const { serverPublicKey: recoveredServerPk, envelope: recoveredEnv } = unmaskResponse(
    loginMaskingKey,
    mNonce,
    mResp,
    suite,
  );

  const recoverResult = recover(
    loginRandomizedPassword,
    recoveredServerPk,
    recoveredEnv,
    deriveKP,
    suite,
    serverIdBytes,
    clientIdBytes,
  );

  // Client AKE finish
  const akeState = {
    clientSecretKeyshare: clientAkeState.clientSecretKeyshare,
    clientNonce: clientAkeState.clientNonce,
    ke1Serialized: ke1Bytes,
  };

  const { ke3, sessionKey: clientSessionKey } = clientAkeFinish(
    recoverResult.clientSecretKey,
    recoveredServerPk,
    ke2,
    akeState,
    clientIdBytes,
    serverIdBytes,
    suite,
  );

  // Server → verify KE3
  const serverSessionKey = serverAkeFinish(ke3, serverAkeState);

  return {
    clientSessionKey,
    serverSessionKey,
    registrationExportKey,
    loginExportKey: recoverResult.exportKey,
    clientPublicKey,
    recoveredClientPublicKey: recoverResult.clientPublicKey,
  };
}

for (const suite of ALL_SUITES) {
  describe(`Full OPAQUE flow: ${suite.name}`, () => {
    it('client and server agree on session key', () => {
      const result = fullOpaqueFlow(
        suite,
        'correct-password',
        'sid.example.com',
        'alice@example.com',
      );
      expect(result.clientSessionKey).toEqual(result.serverSessionKey);
      expect(result.clientSessionKey.length).toBe(suite.oprfOutputSize);
    });

    it('export key is consistent between registration and login', () => {
      const result = fullOpaqueFlow(suite, 'export-key-test', 'sid.example.com', 'bob@example.com');
      expect(result.loginExportKey).toEqual(result.registrationExportKey);
    });

    it('client public key is recovered correctly during login', () => {
      const result = fullOpaqueFlow(suite, 'pk-test', 'sid.example.com', 'carol@example.com');
      expect(result.recoveredClientPublicKey).toEqual(result.clientPublicKey);
    });

    it('different passwords produce different session keys', () => {
      const r1 = fullOpaqueFlow(suite, 'password-1', 'sid.example.com', 'alice@example.com');
      const r2 = fullOpaqueFlow(suite, 'password-2', 'sid.example.com', 'alice@example.com');
      expect(r1.clientSessionKey).not.toEqual(r2.clientSessionKey);
    });

    it('wrong password fails during envelope recovery', () => {
      const group = getGroup(suite.curve);
      const hashFn = getHashFn(suite.hash);
      const oprfKp = oprfGenerateKeyPair(suite.curve);
      const serverKp = group.generateKeypair();
      const serverId = te.encode('sid.example.com');
      const clientId = te.encode('alice@example.com');
      const deriveKP = (seed: Uint8Array) => {
        const secretKey = group.scalarReduce(seed);
        const publicKey = group.serializeElement(group.scalarBaseMult(secretKey));
        return { secretKey, publicKey };
      };

      // Register with correct password
      const correctInput = te.encode('correct-password');
      const { blind: regBlind, blindedElement: regBlinded } = oprfBlind(suite.curve, correctInput);
      const regEval = oprfBlindEvaluate(suite.curve, oprfKp.secretKey, regBlinded);
      const oprfOut = oprfFinalize(suite.curve, correctInput, regBlind, regEval);
      const randPw = deriveRandomizedPassword(oprfOut, suite);
      const storeResult = store(randPw, serverKp.publicKey, deriveKP, suite, serverId, clientId);

      // Login with wrong password
      const wrongInput = te.encode('wrong-password');
      const { blind: loginBlind, blindedElement: loginBlinded } = oprfBlind(
        suite.curve,
        wrongInput,
      );
      const loginEval = oprfBlindEvaluate(suite.curve, oprfKp.secretKey, loginBlinded);
      const wrongOprfOut = oprfFinalize(suite.curve, wrongInput, loginBlind, loginEval);
      const wrongRandPw = deriveRandomizedPassword(wrongOprfOut, suite);
      const wrongMaskingKey = expand(
        hashFn,
        wrongRandPw,
        te.encode('MaskingKey'),
        suite.oprfOutputSize,
      );

      // Unmask + recover with wrong password → should fail
      const { maskingNonce, maskedResponse } = maskResponse(
        storeResult.maskingKey,
        serverKp.publicKey,
        storeResult.envelope,
        suite,
      );
      const { serverPublicKey: recovPk, envelope: recovEnv } = unmaskResponse(
        wrongMaskingKey,
        maskingNonce,
        maskedResponse,
        suite,
      );

      expect(() =>
        recover(wrongRandPw, recovPk, recovEnv, deriveKP, suite, serverId, clientId),
      ).toThrow('Envelope recovery failed');
    });
  });
}

describe('Cross-suite isolation', () => {
  it('same password on different suites produces different keys', () => {
    const r1 = fullOpaqueFlow(
      P384_SHA384,
      'shared-password',
      'sid.example.com',
      'alice@example.com',
    );
    const r2 = fullOpaqueFlow(
      P256_SHA256,
      'shared-password',
      'sid.example.com',
      'alice@example.com',
    );
    expect(r1.clientSessionKey).not.toEqual(r2.clientSessionKey);
    expect(r1.registrationExportKey).not.toEqual(r2.registrationExportKey);
  });
});
