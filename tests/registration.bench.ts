// Real benchmark of the OPAQUE registration roundtrip on the active backend
// (TS in Node — wasm-bindgen --target web doesn't load here, so getBackend() → jsBackend).
import { bench, describe, beforeAll } from 'vitest';
import { getBackend, getBackendName } from '../src/backend/index.js';
import { oprfBlindEvaluate, oprfGenerateKeyPair } from '../src/oprf.js';
import { getSuite, CipherSuiteId } from '../src/suites.js';
import { getGroup } from '../src/group/index.js';
import { validatePasswordClientSide, CE_DEFAULT_POLICY } from '../src/policy.js';
import type { OpaqueBackend } from '../src/backend/types.js';

const suiteId = CipherSuiteId.RISTRETTO255_SHA512;
const suite = getSuite(suiteId);
const group = getGroup(suite.curve);
const oprfKp = oprfGenerateKeyPair(suite.curve);
const serverKp = group.generateKeypair();
const ids = { server: 'dev.structured.id', client: 'admin@structured.id' };
const password = 'HrenVamSID12!';

let backend: OpaqueBackend;
beforeAll(async () => {
  backend = await getBackend();
  // eslint-disable-next-line no-console
  console.log('[bench] backend =', getBackendName());
});

describe('OPAQUE registration roundtrip', () => {
  bench('registrationStart + (server evaluate) + registrationFinish', async () => {
    const { request, state } = await backend.registrationStart(password, suiteId);
    const evaluated = oprfBlindEvaluate(suite.curve, oprfKp.secretKey, request);
    const response = new Uint8Array(suite.elementSize * 2);
    response.set(evaluated, 0);
    response.set(serverKp.publicKey, suite.elementSize);
    await backend.registrationFinish(password, response, state, ids);
  });

  bench('registrationStart only (OPRF blind)', async () => {
    await backend.registrationStart(password, suiteId);
  });
});

describe('password policy validation (TS, Rust-parity)', () => {
  bench('validatePasswordClientSide (CE policy)', () => {
    validatePasswordClientSide(password, CE_DEFAULT_POLICY);
  });
});
