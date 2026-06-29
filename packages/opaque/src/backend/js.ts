/**
 * Pure JS OPAQUE backend using @noble/curves + @noble/hashes.
 *
 * Implements full RFC 9807 OPAQUE protocol (client-side only):
 *   - Registration: blind → finalize (build envelope + record)
 *   - Login: blind + KE1 → recover credentials + 3DH → KE3 + session key
 *
 * Server-side operations (BlindEvaluate, KE2 generation) are NOT implemented
 * here — they live in the Rust `sid-identity` server.
 */
import { expand } from '@noble/hashes/hkdf.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import type { OpaqueBackend } from './types.js';
import { getSuite, type CipherSuiteId, type HashId } from '../suites.js';
import type {
  OpaqueState,
  RegistrationStartResult,
  RegistrationFinishResult,
  LoginStartResult,
  LoginFinishResult,
  Identifiers,
} from '../types.js';
import { getGroup } from '../group/index.js';
import { oprfBlind, oprfFinalize } from '../oprf.js';
import {
  deriveRandomizedPassword,
  store,
  recover,
  unmaskResponse,
  serializeEnvelope,
} from '../key-schedule.js';
import { clientAkeStart, clientAkeFinish, deserializeKE2, serializeKE1 } from '../ake.js';

const te = new TextEncoder();

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getHashFn(hash: HashId): any {
  switch (hash) {
    case 'SHA-256':
      return sha256;
    case 'SHA-384':
      return sha384;
    case 'SHA-512':
      return sha512;
  }
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Derive DH key pair from seed.
 *
 * Uses seed as scalar (reduced mod group order) → publicKey = scalar * G.
 * Returns the reduced scalar as secretKey (scalarSize bytes).
 */
function deriveKeyPairFromSeed(
  group: import('../group/types.js').GroupOps,
  seed: Uint8Array,
): { secretKey: Uint8Array; publicKey: Uint8Array } {
  const secretKey = group.scalarReduce(seed);
  const publicElement = group.scalarBaseMult(secretKey);
  return { secretKey, publicKey: group.serializeElement(publicElement) };
}

export const jsBackend: OpaqueBackend = {
  name: 'js',

  async registrationStart(
    password: string,
    suiteId: CipherSuiteId,
  ): Promise<RegistrationStartResult> {
    const suite = getSuite(suiteId);
    const input = te.encode(password);
    const { blind, blindedElement } = oprfBlind(suite.curve, input);
    return { request: blindedElement, state: { suite: suiteId, blind } };
  },

  async registrationFinish(
    password: string,
    response: Uint8Array,
    state: OpaqueState,
    identifiers: Identifiers,
  ): Promise<RegistrationFinishResult> {
    const suite = getSuite(state.suite);
    const group = getGroup(suite.curve);
    const input = te.encode(password);

    // response = evaluated_message(Noe) || server_public_key(Npk)
    const evaluatedMessage = response.slice(0, suite.elementSize);
    const serverPublicKey = response.slice(suite.elementSize, suite.elementSize * 2);

    // OPRF finalize
    const oprfOutput = oprfFinalize(suite.curve, input, state.blind, evaluatedMessage);
    const randomizedPassword = deriveRandomizedPassword(oprfOutput, suite);

    const deriveKP = (seed: Uint8Array) => deriveKeyPairFromSeed(group, seed);
    const serverIdBytes = te.encode(identifiers.server);
    const clientIdBytes = te.encode(identifiers.client);

    const storeResult = store(
      randomizedPassword,
      serverPublicKey,
      deriveKP,
      suite,
      serverIdBytes,
      clientIdBytes,
    );

    // Registration record: client_public_key || masking_key || envelope
    const record = concat(
      storeResult.clientPublicKey,
      storeResult.maskingKey,
      serializeEnvelope(storeResult.envelope),
    );

    return { record, exportKey: storeResult.exportKey };
  },

  async loginStart(password: string, suiteId: CipherSuiteId): Promise<LoginStartResult> {
    const suite = getSuite(suiteId);
    const input = te.encode(password);
    const { blind, blindedElement } = oprfBlind(suite.curve, input);

    const { ke1, state: akeState } = clientAkeStart(blindedElement, suite);
    const ke1Bytes = serializeKE1(ke1);

    const state: OpaqueState = {
      suite: suiteId,
      blind,
      clientEphemeralSecret: akeState.clientSecretKeyshare,
      clientEphemeralPublic: ke1.clientPublicKeyshare,
      ke1: ke1Bytes,
    };

    return { ke1: ke1Bytes, state };
  },

  async loginFinish(
    password: string,
    ke2Bytes: Uint8Array,
    state: OpaqueState,
    identifiers: Identifiers,
  ): Promise<LoginFinishResult> {
    const suite = getSuite(state.suite);
    const group = getGroup(suite.curve);
    const input = te.encode(password);

    // Deserialize KE2
    const ke2 = deserializeKE2(ke2Bytes, suite);

    // Extract credential response components
    const credResp = ke2.credentialResponse;
    const evaluatedMessage = credResp.slice(0, suite.elementSize);
    const maskingNonce = credResp.slice(suite.elementSize, suite.elementSize + suite.nonceSize);
    const maskedResponse = credResp.slice(suite.elementSize + suite.nonceSize);

    // OPRF finalize
    const oprfOutput = oprfFinalize(suite.curve, input, state.blind, evaluatedMessage);
    const randomizedPassword = deriveRandomizedPassword(oprfOutput, suite);

    // Derive masking_key and unmask response
    const hashFn = getHashFn(suite.hash);
    const maskingKey = expand(
      hashFn,
      randomizedPassword,
      te.encode('MaskingKey'),
      suite.oprfOutputSize,
    );
    const { serverPublicKey, envelope } = unmaskResponse(
      maskingKey,
      maskingNonce,
      maskedResponse,
      suite,
    );

    // Recover credentials from envelope
    const deriveKP = (seed: Uint8Array) => deriveKeyPairFromSeed(group, seed);
    const serverIdBytes = te.encode(identifiers.server);
    const clientIdBytes = te.encode(identifiers.client);

    const recoverResult = recover(
      randomizedPassword,
      serverPublicKey,
      envelope,
      deriveKP,
      suite,
      serverIdBytes,
      clientIdBytes,
    );

    // Reconstruct AKE state from saved values
    const akeState = {
      clientSecretKeyshare: state.clientEphemeralSecret!,
      clientNonce: state.ke1!.slice(suite.elementSize, suite.elementSize + suite.nonceSize),
      ke1Serialized: state.ke1!,
    };

    // Client AKE finish: verify server MAC, produce KE3
    const { ke3, sessionKey } = clientAkeFinish(
      recoverResult.clientSecretKey,
      serverPublicKey,
      ke2,
      akeState,
      clientIdBytes,
      serverIdBytes,
      suite,
    );

    return { ke3, sessionKey, exportKey: recoverResult.exportKey };
  },
};
