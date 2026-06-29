/**
 * OPAQUE key schedule (RFC 9807 Section 4).
 *
 * Implements:
 *   - randomized_password derivation from OPRF output
 *   - Store: envelope creation during registration
 *   - Recover: envelope recovery during login
 *   - CreateCleartextCredentials
 *   - Credential response masking/unmasking
 */
import { extract, expand } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import type { CipherSuite, HashId } from './suites.js';

// ── Hash function resolution ──

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- sha256/384/512 have incompatible internal types
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

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i]! ^ b[i]!;
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

// ── Envelope ──

export interface Envelope {
  nonce: Uint8Array;
  authTag: Uint8Array;
}

export function serializeEnvelope(env: Envelope): Uint8Array {
  return concat(env.nonce, env.authTag);
}

export function deserializeEnvelope(data: Uint8Array, suite: CipherSuite): Envelope {
  const nonce = data.slice(0, suite.nonceSize);
  const authTag = data.slice(suite.nonceSize, suite.nonceSize + suite.macSize);
  return { nonce, authTag };
}

/** Envelope wire size: Nn + Nm. */
export function envelopeSize(suite: CipherSuite): number {
  return suite.nonceSize + suite.macSize;
}

// ── CleartextCredentials ──

/**
 * CreateCleartextCredentials per RFC 9807 Section 4.
 *
 * server_public_key || I2OSP(len(server_identity), 2) || server_identity
 *                   || I2OSP(len(client_identity), 2) || client_identity
 */
export function createCleartextCredentials(
  serverPublicKey: Uint8Array,
  clientPublicKey: Uint8Array,
  serverIdentity: Uint8Array | undefined,
  clientIdentity: Uint8Array | undefined,
): Uint8Array {
  const serverId = serverIdentity ?? serverPublicKey;
  const clientId = clientIdentity ?? clientPublicKey;
  return concat(
    serverPublicKey,
    i2osp(serverId.length, 2),
    serverId,
    i2osp(clientId.length, 2),
    clientId,
  );
}

// ── randomized_password ──

/**
 * Derive randomized_password from OPRF output.
 *
 * Per RFC 9807:
 *   stretched = Stretch(oprf_output)   // identity for now (no KSF)
 *   randomized_password = Extract("", oprf_output || stretched)
 */
export function deriveRandomizedPassword(oprfOutput: Uint8Array, suite: CipherSuite): Uint8Array {
  const hashFn = getHashFn(suite.hash);
  // Stretch = identity (no KSF applied). In production, Argon2id would go here.
  const stretched = oprfOutput;
  const ikm = concat(oprfOutput, stretched);
  return extract(hashFn, ikm, new Uint8Array(0));
}

// ── Store (Registration) ──

export interface StoreResult {
  envelope: Envelope;
  clientPublicKey: Uint8Array;
  maskingKey: Uint8Array;
  exportKey: Uint8Array;
}

/**
 * Store: create envelope during registration.
 *
 * @param randomizedPassword - Derived from OPRF output.
 * @param serverPublicKey - Server's static public key.
 * @param deriveKeyPair - Function to derive DH key pair from seed.
 * @param serverIdentity - Server identity (defaults to server public key).
 * @param clientIdentity - Client identity (defaults to derived client public key).
 */
export function store(
  randomizedPassword: Uint8Array,
  serverPublicKey: Uint8Array,
  deriveKeyPair: (seed: Uint8Array) => { secretKey: Uint8Array; publicKey: Uint8Array },
  suite: CipherSuite,
  serverIdentity?: Uint8Array,
  clientIdentity?: Uint8Array,
): StoreResult {
  const hashFn = getHashFn(suite.hash);
  const Nh = suite.oprfOutputSize;
  const Nseed = suite.scalarSize;

  const envelopeNonce = randomBytes(suite.nonceSize);

  const maskingKey = expand(hashFn, randomizedPassword, te.encode('MaskingKey'), Nh);
  const authKey = expand(
    hashFn,
    randomizedPassword,
    concat(envelopeNonce, te.encode('AuthKey')),
    Nh,
  );
  const exportKey = expand(
    hashFn,
    randomizedPassword,
    concat(envelopeNonce, te.encode('ExportKey')),
    Nh,
  );
  const seed = expand(
    hashFn,
    randomizedPassword,
    concat(envelopeNonce, te.encode('PrivateKey')),
    Nseed,
  );

  const { publicKey: clientPublicKey } = deriveKeyPair(seed);

  const cleartextCredentials = createCleartextCredentials(
    serverPublicKey,
    clientPublicKey,
    serverIdentity,
    clientIdentity,
  );

  const authTag = hmac(hashFn, authKey, concat(envelopeNonce, cleartextCredentials));

  const envelope: Envelope = { nonce: envelopeNonce, authTag };

  return { envelope, clientPublicKey, maskingKey, exportKey };
}

// ── Recover (Login) ──

export interface RecoverResult {
  clientSecretKey: Uint8Array;
  clientPublicKey: Uint8Array;
  exportKey: Uint8Array;
}

/**
 * Recover: recover credentials from envelope during login.
 *
 * @throws {Error} If envelope auth_tag verification fails (wrong password).
 */
export function recover(
  randomizedPassword: Uint8Array,
  serverPublicKey: Uint8Array,
  envelope: Envelope,
  deriveKeyPair: (seed: Uint8Array) => { secretKey: Uint8Array; publicKey: Uint8Array },
  suite: CipherSuite,
  serverIdentity?: Uint8Array,
  clientIdentity?: Uint8Array,
): RecoverResult {
  const hashFn = getHashFn(suite.hash);
  const Nh = suite.oprfOutputSize;
  const Nseed = suite.scalarSize;

  const authKey = expand(
    hashFn,
    randomizedPassword,
    concat(envelope.nonce, te.encode('AuthKey')),
    Nh,
  );
  const exportKey = expand(
    hashFn,
    randomizedPassword,
    concat(envelope.nonce, te.encode('ExportKey')),
    Nh,
  );
  const seed = expand(
    hashFn,
    randomizedPassword,
    concat(envelope.nonce, te.encode('PrivateKey')),
    Nseed,
  );

  const { secretKey: clientSecretKey, publicKey: clientPublicKey } = deriveKeyPair(seed);

  const cleartextCredentials = createCleartextCredentials(
    serverPublicKey,
    clientPublicKey,
    serverIdentity,
    clientIdentity,
  );

  const expectedTag = hmac(hashFn, authKey, concat(envelope.nonce, cleartextCredentials));

  if (!constantTimeEqual(envelope.authTag, expectedTag)) {
    throw new Error('Envelope recovery failed: invalid auth tag (wrong password?)');
  }

  return { clientSecretKey, clientPublicKey, exportKey };
}

// ── Credential Response Masking ──

/**
 * Mask credential response (server side).
 *
 * masked_response = xor(pad, server_public_key || envelope)
 * pad = Expand(masking_key, masking_nonce || "CredentialResponsePad", Npk + Nn + Nm)
 */
export function maskResponse(
  maskingKey: Uint8Array,
  serverPublicKey: Uint8Array,
  envelope: Envelope,
  suite: CipherSuite,
): { maskingNonce: Uint8Array; maskedResponse: Uint8Array } {
  const hashFn = getHashFn(suite.hash);
  const maskingNonce = randomBytes(suite.nonceSize);
  const padLen = suite.elementSize + envelopeSize(suite);
  const pad = expand(
    hashFn,
    maskingKey,
    concat(maskingNonce, te.encode('CredentialResponsePad')),
    padLen,
  );
  const plaintext = concat(serverPublicKey, serializeEnvelope(envelope));
  const maskedResponse = xor(pad, plaintext);
  return { maskingNonce, maskedResponse };
}

/**
 * Unmask credential response (client side).
 *
 * Returns server_public_key and envelope.
 */
export function unmaskResponse(
  maskingKey: Uint8Array,
  maskingNonce: Uint8Array,
  maskedResponse: Uint8Array,
  suite: CipherSuite,
): { serverPublicKey: Uint8Array; envelope: Envelope } {
  const hashFn = getHashFn(suite.hash);
  const padLen = maskedResponse.length;
  const pad = expand(
    hashFn,
    maskingKey,
    concat(maskingNonce, te.encode('CredentialResponsePad')),
    padLen,
  );
  const plaintext = xor(pad, maskedResponse);
  const serverPublicKey = plaintext.slice(0, suite.elementSize);
  const envelope = deserializeEnvelope(plaintext.slice(suite.elementSize), suite);
  return { serverPublicKey, envelope };
}
