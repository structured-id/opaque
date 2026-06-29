// ── Client ──
export { OpaqueClient } from './client.js';
export type { OpaqueClientConfig } from './client.js';

// ── Types ──
export type {
  OpaqueState,
  RegistrationStartResult,
  RegistrationFinishResult,
  LoginStartResult,
  LoginFinishResult,
  Identifiers,
} from './types.js';

// ── Cipher suites (RFC 9807 standard + SID extensions) ──
export {
  CurveId,
  CipherSuiteId,
  DEFAULT_SUITE,
  SUITES,
  getSuite,
  getSuiteByCurve,
  RISTRETTO255_SHA512,
  P256_SHA256,
  P384_SHA384,
  P521_SHA512,
} from './suites.js';
export type { CipherSuite, HashId } from './suites.js';

// ── Backend ──
export { getBackend, setBackend, getBackendName } from './backend/index.js';
export type { OpaqueBackend } from './backend/types.js';

// ── Password policy (pure-TS, byte-for-byte parity with Rust sid_crypto::policy) ──
export {
  validatePasswordClientSide,
  getPolicy,
  CE_DEFAULT_POLICY,
  CE_POLICY_VERSION,
} from './policy.js';
export type { PolicyParams } from './policy.js';

// ── Group operations ──
export { getGroup } from './group/index.js';
export type { GroupOps, GroupElement } from './group/types.js';

// ── OPRF ──
export {
  oprfBlind,
  oprfBlindEvaluate,
  oprfFinalize,
  oprfEvaluate,
  oprfGenerateKeyPair,
} from './oprf.js';
export type { OprfBlindResult, OprfKeyPair } from './oprf.js';

// ── Key Schedule ──
export {
  deriveRandomizedPassword,
  store,
  recover,
  maskResponse,
  unmaskResponse,
  createCleartextCredentials,
  serializeEnvelope,
  deserializeEnvelope,
  envelopeSize,
} from './key-schedule.js';
export type { Envelope, StoreResult, RecoverResult } from './key-schedule.js';

// ── AKE ──
export {
  clientAkeStart,
  clientAkeFinish,
  serverAkeRespond,
  serverAkeFinish,
  serializeKE1,
  serializeKE2,
  deserializeKE2,
} from './ake.js';
export type { KE1, KE2, KE3, ClientAkeState, ServerAkeState } from './ake.js';
