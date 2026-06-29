/**
 * OPAQUE 3DH AKE (RFC 9807 Section 6).
 *
 * Triple Diffie-Hellman Authenticated Key Exchange:
 *   DH1 = client_secret × server_public
 *   DH2 = client_ephemeral_secret × server_public
 *   DH3 = client_ephemeral_secret × server_ephemeral_public
 *
 * Uses TLS 1.3 Expand-Label for key derivation.
 */
import { extract, expand } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import type { CipherSuite, HashId } from './suites.js';
import { getGroup } from './group/index.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type HashFn = any;

function getHashFn(hash: HashId): HashFn {
  switch (hash) {
    case 'SHA-256':
      return sha256;
    case 'SHA-384':
      return sha384;
    case 'SHA-512':
      return sha512;
  }
}

function hashDigest(hash: HashId, data: Uint8Array): Uint8Array {
  switch (hash) {
    case 'SHA-256':
      return sha256(data);
    case 'SHA-384':
      return sha384(data);
    case 'SHA-512':
      return sha512(data);
  }
}

const te = new TextEncoder();

// ── Utility ──

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

function i2osp(value: number, length: number): Uint8Array {
  const result = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    result[i] = value & 0xff;
    value >>= 8;
  }
  return result;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

// ── TLS 1.3 Expand-Label (RFC 8446 Section 7.1) ──

/**
 * Expand-Label per RFC 9807:
 *   CustomLabel = I2OSP(Length, 2) || I2OSP(len("OPAQUE-" + Label), 1)
 *              || "OPAQUE-" + Label || I2OSP(len(Context), 1) || Context
 */
function expandLabel(
  hashFn: HashFn,
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
): Uint8Array {
  const fullLabel = te.encode('OPAQUE-' + label);
  const customLabel = concat(
    i2osp(length, 2),
    i2osp(fullLabel.length, 1),
    fullLabel,
    i2osp(context.length, 1),
    context,
  );
  return expand(hashFn, secret, customLabel, length);
}

function deriveSecret(
  hashFn: HashFn,
  secret: Uint8Array,
  label: string,
  transcriptHash: Uint8Array,
  Nx: number,
): Uint8Array {
  return expandLabel(hashFn, secret, label, transcriptHash, Nx);
}

// ── AKE Key Derivation ──

interface AkeKeys {
  Km2: Uint8Array;
  Km3: Uint8Array;
  sessionKey: Uint8Array;
}

/**
 * DeriveKeys per RFC 9807 Section 6.4.
 *
 * ikm = DH1 || DH2 || DH3
 * prk = Extract("", ikm)
 * handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
 * session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
 * Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
 * Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
 */
function deriveAkeKeys(ikm: Uint8Array, preamble: Uint8Array, suite: CipherSuite): AkeKeys {
  const hashFn = getHashFn(suite.hash);
  const Nx = suite.oprfOutputSize; // Nx = Nh for all suites

  const prk = extract(hashFn, ikm, new Uint8Array(0));
  const transcriptHash = hashDigest(suite.hash, preamble);
  const emptyHash = new Uint8Array(0);

  const handshakeSecret = deriveSecret(hashFn, prk, 'HandshakeSecret', transcriptHash, Nx);
  const sessionKey = deriveSecret(hashFn, prk, 'SessionKey', transcriptHash, Nx);
  const Km2 = deriveSecret(hashFn, handshakeSecret, 'ServerMAC', emptyHash, Nx);
  const Km3 = deriveSecret(hashFn, handshakeSecret, 'ClientMAC', emptyHash, Nx);

  return { Km2, Km3, sessionKey };
}

// ── Preamble ──

/**
 * Build AKE preamble (transcript).
 *
 * preamble = "OPAQUEv1-"
 *   || I2OSP(len(context), 2) || context
 *   || I2OSP(len(client_identity), 2) || client_identity
 *   || ke1
 *   || I2OSP(len(server_identity), 2) || server_identity
 *   || inner_ke2 (credential_response || server_nonce || server_public_keyshare)
 */
function buildPreamble(
  context: Uint8Array,
  clientIdentity: Uint8Array,
  ke1: Uint8Array,
  serverIdentity: Uint8Array,
  innerKe2: Uint8Array,
): Uint8Array {
  return concat(
    te.encode('OPAQUEv1-'),
    i2osp(context.length, 2),
    context,
    i2osp(clientIdentity.length, 2),
    clientIdentity,
    ke1,
    i2osp(serverIdentity.length, 2),
    serverIdentity,
    innerKe2,
  );
}

// ── KE Messages ──

/**
 * KE1 = credential_request || client_nonce || client_public_keyshare
 */
export interface KE1 {
  credentialRequest: Uint8Array;
  clientNonce: Uint8Array;
  clientPublicKeyshare: Uint8Array;
}

export function serializeKE1(ke1: KE1): Uint8Array {
  return concat(ke1.credentialRequest, ke1.clientNonce, ke1.clientPublicKeyshare);
}

/**
 * KE2 = credential_response || server_nonce || server_public_keyshare || server_mac
 */
export interface KE2 {
  credentialResponse: Uint8Array;
  serverNonce: Uint8Array;
  serverPublicKeyshare: Uint8Array;
  serverMac: Uint8Array;
}

export function serializeKE2(ke2: KE2): Uint8Array {
  return concat(ke2.credentialResponse, ke2.serverNonce, ke2.serverPublicKeyshare, ke2.serverMac);
}

export function deserializeKE2(data: Uint8Array, suite: CipherSuite): KE2 {
  // credential_response = evaluated_message(Noe) + masking_nonce(Nn) + masked_response(Npk + Nn + Nm)
  const credRespLen =
    suite.elementSize + suite.nonceSize + (suite.elementSize + suite.nonceSize + suite.macSize);
  let offset = 0;
  const credentialResponse = data.slice(offset, offset + credRespLen);
  offset += credRespLen;
  const serverNonce = data.slice(offset, offset + suite.nonceSize);
  offset += suite.nonceSize;
  const serverPublicKeyshare = data.slice(offset, offset + suite.elementSize);
  offset += suite.elementSize;
  const serverMac = data.slice(offset, offset + suite.macSize);
  return { credentialResponse, serverNonce, serverPublicKeyshare, serverMac };
}

/** KE3 = client_mac */
export type KE3 = Uint8Array;

// ── Client AKE State ──

export interface ClientAkeState {
  clientSecretKeyshare: Uint8Array;
  clientNonce: Uint8Array;
  ke1Serialized: Uint8Array;
}

// ── Client AKE ──

/**
 * Client: generate KE1 (start AKE).
 *
 * Generates ephemeral key pair + nonce. Returns KE1 and state.
 */
export function clientAkeStart(
  credentialRequest: Uint8Array,
  suite: CipherSuite,
): { ke1: KE1; state: ClientAkeState } {
  const group = getGroup(suite.curve);
  const { secretKey: clientSecretKeyshare, publicKey: clientPublicKeyshare } =
    group.generateKeypair();
  const clientNonce = randomBytes(suite.nonceSize);

  const ke1: KE1 = { credentialRequest, clientNonce, clientPublicKeyshare };
  const ke1Serialized = serializeKE1(ke1);

  return {
    ke1,
    state: { clientSecretKeyshare, clientNonce, ke1Serialized },
  };
}

/**
 * Client: process KE2, verify server MAC, produce KE3.
 *
 * @param clientSecretKey - Client's long-term secret key (recovered from envelope).
 * @param serverPublicKey - Server's long-term public key (from credential response).
 * @param ke2 - Server's KE2 message.
 * @param state - Client's AKE state from clientAkeStart.
 * @param clientIdentity - Client identity bytes.
 * @param serverIdentity - Server identity bytes.
 * @param context - Optional context string (default empty).
 *
 * @returns KE3 (client MAC) + session key.
 */
export function clientAkeFinish(
  clientSecretKey: Uint8Array,
  serverPublicKey: Uint8Array,
  ke2: KE2,
  state: ClientAkeState,
  clientIdentity: Uint8Array,
  serverIdentity: Uint8Array,
  suite: CipherSuite,
  context: Uint8Array = new Uint8Array(0),
): { ke3: KE3; sessionKey: Uint8Array } {
  const group = getGroup(suite.curve);
  const hashFn = getHashFn(suite.hash);

  // Triple DH
  const dh1 = group.ecdh(clientSecretKey, serverPublicKey);
  const dh2 = group.ecdh(state.clientSecretKeyshare, serverPublicKey);
  const dh3 = group.ecdh(state.clientSecretKeyshare, ke2.serverPublicKeyshare);
  const ikm = concat(dh1, dh2, dh3);

  // Preamble
  const innerKe2 = concat(ke2.credentialResponse, ke2.serverNonce, ke2.serverPublicKeyshare);
  const preamble = buildPreamble(
    context,
    clientIdentity,
    state.ke1Serialized,
    serverIdentity,
    innerKe2,
  );

  // Derive keys
  const { Km2, Km3, sessionKey } = deriveAkeKeys(ikm, preamble, suite);

  // Verify server MAC
  const preambleHash = hashDigest(suite.hash, preamble);
  const expectedServerMac = hmac(hashFn, Km2, preambleHash);
  if (!constantTimeEqual(ke2.serverMac, expectedServerMac)) {
    throw new Error('AKE failed: invalid server MAC');
  }

  // Compute client MAC
  const clientMac = hmac(hashFn, Km3, hashDigest(suite.hash, concat(preamble, expectedServerMac)));

  return { ke3: clientMac, sessionKey };
}

// ── Server AKE ──

export interface ServerAkeState {
  sessionKey: Uint8Array;
  expectedClientMac: Uint8Array;
}

/**
 * Server: generate KE2 (respond to KE1).
 *
 * @returns KE2 + state (for verifying KE3 later).
 */
export function serverAkeRespond(
  serverSecretKey: Uint8Array,
  serverPublicKey: Uint8Array,
  clientPublicKey: Uint8Array,
  credentialResponse: Uint8Array,
  ke1: KE1,
  clientIdentity: Uint8Array,
  serverIdentity: Uint8Array,
  suite: CipherSuite,
  context: Uint8Array = new Uint8Array(0),
): { ke2: KE2; state: ServerAkeState } {
  const group = getGroup(suite.curve);
  const hashFn = getHashFn(suite.hash);

  // Ephemeral keypair
  const { secretKey: serverSecretKeyshare, publicKey: serverPublicKeyshare } =
    group.generateKeypair();
  const serverNonce = randomBytes(suite.nonceSize);

  // Triple DH (server perspective: swap client/server roles)
  const dh1 = group.ecdh(serverSecretKey, clientPublicKey);
  const dh2 = group.ecdh(serverSecretKey, ke1.clientPublicKeyshare);
  const dh3 = group.ecdh(serverSecretKeyshare, ke1.clientPublicKeyshare);
  const ikm = concat(dh1, dh2, dh3);

  // Preamble
  const ke1Serialized = serializeKE1(ke1);
  const innerKe2 = concat(credentialResponse, serverNonce, serverPublicKeyshare);
  const preamble = buildPreamble(context, clientIdentity, ke1Serialized, serverIdentity, innerKe2);

  // Derive keys
  const { Km2, Km3, sessionKey } = deriveAkeKeys(ikm, preamble, suite);

  // Server MAC
  const preambleHash = hashDigest(suite.hash, preamble);
  const serverMac = hmac(hashFn, Km2, preambleHash);

  // Expected client MAC (for later verification)
  const expectedClientMac = hmac(hashFn, Km3, hashDigest(suite.hash, concat(preamble, serverMac)));

  const ke2: KE2 = { credentialResponse, serverNonce, serverPublicKeyshare, serverMac };

  return { ke2, state: { sessionKey, expectedClientMac } };
}

/**
 * Server: verify KE3 (client MAC).
 *
 * @returns session key if KE3 is valid.
 * @throws {Error} If client MAC is invalid.
 */
export function serverAkeFinish(ke3: KE3, state: ServerAkeState): Uint8Array {
  if (!constantTimeEqual(ke3, state.expectedClientMac)) {
    throw new Error('AKE failed: invalid client MAC');
  }
  return state.sessionKey;
}
