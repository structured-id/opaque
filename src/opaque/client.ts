/**
 * OPAQUE client on Pallas (RFC 9807), byte-identical to opaque-ke 4.0.1 over
 * the reference `PallasCipherSuite`: OPRF on Pallas (oprf.ts), TripleDH over
 * Pallas with SHA-256, Argon2id key stretching with its default parameters.
 *
 * Every random draw goes through the given {@link RandomSource} in the order
 * the reference consumes its RNG, and the client states are the reference's
 * `ClientRegistration` / `ClientLogin` serializations, so the two kernels
 * exchange the same bytes on every message.
 */
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Pallas, type Point } from "../curve.js";
import { FP_MODULUS } from "../field.js";
import { secureRandom, type RandomSource } from "../random.js";
import {
  concat,
  equalBytes,
  fromBase64,
  i2osp2,
  Reader,
  toBase64,
  utf8,
} from "./bytes.js";
import {
  blindWith,
  deriveKey,
  deserializeElement,
  deserializeScalar,
  finalize,
  randomScalar,
  serializeScalar,
} from "./oprf.js";

/** Nonce, hash output, element and key lengths of the suite. */
const LEN = 32;

/**
 * The client KSF: opaque-ke's `Argon2::default()` (Argon2id v0x13, 19 MiB,
 * two passes, one lane) over the OPRF output with a zero 16-byte salt.
 */
export const KSF = { t: 2, m: 19 * 1024, p: 1 } as const;
const KSF_SALT = new Uint8Array(16);

/** RFC 9807 §6.4.2 DeriveDiffieHellmanKeyPair info. */
const DERIVE_DH = utf8("OPAQUE-DeriveDiffieHellmanKeyPair");

/**
 * Registration starts tried for a blind the circuit can hold (below the
 * base-field modulus; each start misses with probability about 2^-126), as
 * the reference client does.
 */
const BLIND_ATTEMPTS = 4;

export interface ClientStart {
  /** The message to send: RegistrationRequest or CredentialRequest. */
  request: Uint8Array;
  /** The client state for the finish, base64; keep it local. */
  state: string;
}

export interface ClientLoginFinish {
  /** KE3, the CredentialFinalization to send. */
  finalization: Uint8Array;
  /** The session key both sides derived. */
  sessionKey: Uint8Array;
  /** The export key of the credential. */
  exportKey: Uint8Array;
}

function hkdfExpand(prk: Uint8Array, info: Uint8Array, length = LEN) {
  return expand(sha256, prk, info, length);
}

/** Point `sk·pk` as the 32 bytes Diffie-Hellman outputs. */
const dh = (sk: bigint, pk: Point): Uint8Array =>
  Pallas.toBytes(Pallas.scalarMul(sk, pk));

/** A received public key; the identity is refused (RFC 9807 §6.4.1). */
function deserializePublicKey(bytes: Uint8Array): NonNullable<Point> {
  const p = Pallas.fromBytes(bytes);
  if (p === null) throw new Error("public key: the identity is not accepted");
  return p;
}

/**
 * randomized_pwd: HKDF-Extract over the OPRF output and its stretched value
 * (RFC 9807 §6.3.1, opaque-ke `get_password_derived_key`).
 */
async function randomizedPassword(
  password: Uint8Array,
  blind: bigint,
  evaluated: Uint8Array,
): Promise<Uint8Array> {
  const oprfOutput = finalize(password, blind, evaluated);
  const stretched = await argon2idAsync(oprfOutput, KSF_SALT, {
    ...KSF,
    dkLen: LEN,
  });
  return extract(sha256, concat([oprfOutput, stretched]));
}

/** The client's static key pair from the envelope nonce (RFC 9807 §4.1.2). */
function envelopeKeyPair(prk: Uint8Array, nonce: Uint8Array) {
  const seed = hkdfExpand(prk, concat([nonce, utf8("PrivateKey")]));
  const sk = deriveKey(seed, DERIVE_DH);
  return { sk, pk: Pallas.scalarMul(sk, Pallas.GENERATOR) };
}

/** The envelope MAC over `nonce ‖ server_pk ‖ id_s ‖ id_u`, identities = keys. */
function envelopeMac(
  prk: Uint8Array,
  nonce: Uint8Array,
  serverPk: Uint8Array,
  clientPk: Uint8Array,
): { mac: Uint8Array; exportKey: Uint8Array } {
  const authKey = hkdfExpand(prk, concat([nonce, utf8("AuthKey")]));
  const exportKey = hkdfExpand(prk, concat([nonce, utf8("ExportKey")]));
  const mac = hmac(
    sha256,
    authKey,
    concat([nonce, serverPk, i2osp2(LEN), serverPk, i2osp2(LEN), clientPk]),
  );
  return { mac, exportKey };
}

/**
 * Start registering `password` (a first password, a change or a reset): the
 * RegistrationRequest and the state. The blind is drawn until the circuit can
 * hold it, so the proof over this request never needs a new start.
 */
export function registrationStart(
  password: Uint8Array,
  rng: RandomSource = secureRandom,
): ClientStart {
  if (password.length === 0) throw new Error("password cannot be empty");
  for (let i = 0; i < BLIND_ATTEMPTS; i++) {
    const blind = randomScalar(rng);
    if (blind === 0n || blind >= FP_MODULUS) continue;
    const request = blindWith(password, blind);
    return {
      request,
      state: toBase64(concat([serializeScalar(blind), request])),
    };
  }
  throw new Error("no usable OPRF blind drawn; the random source is broken");
}

/** The blind and request a registration state holds. */
export function registrationState(state: string): {
  blind: bigint;
  request: Uint8Array;
} {
  const r = new Reader(fromBase64(state, "state"), "state");
  const blind = deserializeScalar(r.take(LEN));
  const request = r.take(LEN);
  r.end();
  deserializeElement(request);
  return { blind, request };
}

/**
 * Finish a registration against the server's RegistrationResponse: the
 * RegistrationRecord (client_pk ‖ masking_key ‖ envelope).
 */
export async function registrationFinish(
  password: Uint8Array,
  state: string,
  response: Uint8Array,
  rng: RandomSource = secureRandom,
): Promise<Uint8Array> {
  const { blind, request } = registrationState(state);
  const r = new Reader(response, "registration response");
  const evaluated = r.take(LEN);
  const serverPk = r.take(LEN);
  r.end();
  deserializeElement(evaluated);
  deserializePublicKey(serverPk);
  if (equalBytes(evaluated, request))
    throw new Error("registration response reflects the request");

  const prk = await randomizedPassword(password, blind, evaluated);
  const maskingKey = hkdfExpand(prk, utf8("MaskingKey"));
  const nonce = rng(LEN);
  const { pk } = envelopeKeyPair(prk, nonce);
  const clientPk = Pallas.toBytes(pk);
  const { mac } = envelopeMac(prk, nonce, serverPk, clientPk);
  return concat([clientPk, maskingKey, nonce, mac]);
}

/**
 * Start signing in: the CredentialRequest (blinded element ‖ KE1) and the
 * state (blind ‖ request ‖ ephemeral key ‖ nonce).
 */
export function loginStart(
  password: Uint8Array,
  rng: RandomSource = secureRandom,
): ClientStart {
  if (password.length === 0) throw new Error("password cannot be empty");
  const blind = randomScalar(rng);
  const blinded = blindWith(password, blind);
  const eSk = deriveKey(rng(LEN), DERIVE_DH);
  const nonce = rng(LEN);
  const ePk = Pallas.toBytes(Pallas.scalarMul(eSk, Pallas.GENERATOR));
  const request = concat([blinded, nonce, ePk]);
  return {
    request,
    state: toBase64(
      concat([serializeScalar(blind), request, serializeScalar(eSk), nonce]),
    ),
  };
}

/** HKDF-Expand-Label of the key schedule (RFC 9807 §6.4.2). */
function expandLabel(secret: Uint8Array, label: string, context: Uint8Array) {
  const full = concat([utf8("OPAQUE-"), utf8(label)]);
  return hkdfExpand(
    secret,
    concat([
      i2osp2(LEN),
      Uint8Array.of(full.length),
      full,
      Uint8Array.of(context.length),
      context,
    ]),
  );
}

/**
 * The sign-in did not verify: a wrong password, a response not made for this
 * credential or another context (RFC 9807 §6.4 envelope recovery or server
 * MAC). Recognised by its `name`, so a kernel and every copy of this package
 * report it alike; any other failure of a sign-in is not this error.
 */
export class ZkppInvalidLoginError extends Error {
  constructor() {
    super("invalid login");
    this.name = "ZkppInvalidLoginError";
  }
}

/**
 * Finish signing in against the server's CredentialResponse under `context`
 * (RFC 9807 §6): KE3 and the session key. The context is empty (the RFC's
 * default) for an ordinary sign-in and the operation's own inside another
 * operation; the server must use the same. A wrong password, a response not
 * made for this credential or another context fails here.
 */
export async function loginFinish(
  password: Uint8Array,
  state: string,
  response: Uint8Array,
  context: Uint8Array = new Uint8Array(0),
): Promise<ClientLoginFinish> {
  if (context.length > 0xffff) throw new Error("OPAQUE context too long");
  const s = new Reader(fromBase64(state, "state"), "state");
  const blind = deserializeScalar(s.take(LEN));
  const request = s.take(3 * LEN);
  const eSk = deserializeScalar(s.take(LEN));
  // The KE1 nonce; the transcript takes it from the request it is part of.
  s.take(LEN);
  s.end();

  const r = new Reader(response, "credential response");
  const evaluated = r.take(LEN);
  const maskingNonce = r.take(LEN);
  const masked = r.take(3 * LEN);
  const serverNonce = r.take(LEN);
  const serverEPk = r.take(LEN);
  const serverMac = r.take(LEN);
  r.end();
  deserializeElement(evaluated);
  if (equalBytes(evaluated, request.subarray(0, LEN)))
    throw new Error("credential response reflects the request");

  const prk = await randomizedPassword(password, blind, evaluated);
  const maskingKey = hkdfExpand(prk, utf8("MaskingKey"));
  const pad = hkdfExpand(
    maskingKey,
    concat([maskingNonce, utf8("CredentialResponsePad")]),
    3 * LEN,
  );
  const unmasked = masked.map((b, i) => b ^ pad[i]);
  const serverPk = unmasked.slice(0, LEN);
  const envelopeNonce = unmasked.slice(LEN, 2 * LEN);
  const envelopeTag = unmasked.slice(2 * LEN);

  const invalid = new ZkppInvalidLoginError();
  let serverPoint: NonNullable<Point>;
  try {
    serverPoint = deserializePublicKey(serverPk);
  } catch {
    throw invalid;
  }
  const { sk, pk } = envelopeKeyPair(prk, envelopeNonce);
  const clientPk = Pallas.toBytes(pk);
  const { mac, exportKey } = envelopeMac(
    prk,
    envelopeNonce,
    serverPk,
    clientPk,
  );
  if (!equalBytes(mac, envelopeTag)) throw invalid;

  const serverE = deserializePublicKey(serverEPk);
  const preamble = concat([
    utf8("OPAQUEv1-"),
    i2osp2(context.length),
    context,
    i2osp2(LEN),
    clientPk,
    request,
    i2osp2(LEN),
    serverPk,
    evaluated,
    maskingNonce,
    masked,
    serverNonce,
    serverEPk,
  ]);
  const ikm = concat([dh(eSk, serverE), dh(eSk, serverPoint), dh(sk, serverE)]);
  const extracted = extract(sha256, ikm);
  const transcriptHash = sha256(preamble);
  const handshake = expandLabel(extracted, "HandshakeSecret", transcriptHash);
  const sessionKey = expandLabel(extracted, "SessionKey", transcriptHash);
  const km2 = expandLabel(handshake, "ServerMAC", new Uint8Array(0));
  const km3 = expandLabel(handshake, "ClientMAC", new Uint8Array(0));

  if (!equalBytes(hmac(sha256, km2, transcriptHash), serverMac)) throw invalid;
  const finalization = hmac(sha256, km3, sha256(concat([preamble, serverMac])));
  return { finalization, sessionKey, exportKey };
}
