// TS halo2 prover (create_proof) interop, step-by-step vs the deterministic Rust
// reference (toy circuit a·b=c, k=4, counter RNG). Vectors from toy_proof.rs +
// permutation fixture (fixtures/toy-perm.json) dumped via HALO2_DUMP.
import { describe, it, expect } from 'vitest';
import { Vesta } from '../src/zkpp/curve.js';
import { Transcript } from '../src/zkpp/transcript.js';
import { Fp } from '../src/zkpp/field.js';
import {
  CounterRng,
  commitAdvice,
  permutationZ,
  DELTA,
  type ProvingParams,
} from '../src/zkpp/prover.js';
import perm from './fixtures/toy-perm.json';

const bytes = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const pt = (h: string) => Vesta.fromBytes(bytes(h)) as { x: bigint; y: bigint };
const fe = (v: bigint) => hex(Fp.toBytes(v));
const leHex = (h: string): bigint => {
  let v = 0n;
  for (let i = h.length - 2; i >= 0; i -= 2)
    v = (v << 8n) | BigInt(parseInt(h.slice(i, i + 2), 16));
  return v;
};
const f16 = (h: string) =>
  Array.from({ length: 16 }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));

const G_LAGRANGE = [
  'e436eff1671007968da74b6be6ccb48e913341be55133cd2d721f6091d0fff98',
  'b3439dbb07326b3209dec6edbd14c0a21984916da7ee77465923d81ba178d4b1',
  '8111cc4cd91589050939cf232cd5ead5e360da19c1f4940d821e8080c08d8309',
  'ac9cb225b81c873e7c131d1dd7e5c7daba511fc4d006ee538c4e9e568bb5141a',
  'ec2d1ca83b63728246bfeaa7e334b50236a00b32382bac3cd452a60ffa753e1e',
  'f61a297cd3dc427f6f0878bcb870e40c79492e723d5757ab411390a20859c090',
  'c350271718b7a9010d1307f44633ffa1ca0d64e83f6dde32a6279581a0895e92',
  '69ea747d69099561fd95c305c3ff5dfbf54520b31876db320e1c1f22f7037aab',
  '90533f1b3b25e500385876fa152d4e0071a9f5d348c74934b95c1b654ffd3003',
  'e6b7a50c72017331a6200cda6661d5a2e392ac36d9a29b44a2089f2c9d49639c',
  '7268449bd6fde6af08b7fb1f28caf7247eaa63322adea96b427cb5ea2fed0403',
  'f4cc877cce9bcd35c98850b7aee671cacc7cb097713878c12069b9d260973b97',
  '64f0e4ca677800fe3d8892840b641168ffa6c26d905c02aa3f6897f6307e113f',
  '8f263734f7348cb730fafe1cebfb2f493bcaa4fe1d00cc7860f6801fc7506400',
  '5b842ab22e8b65c13b4110369977b17ce90f3dc577656a9aea90db774eb4c329',
  '67f36a53588cc7301e53f167cd8a57a109f4ff30256ac61eabce7dae25ef2fae',
].map(pt);
const W = pt('7520d96f3e5cd41760367151608b54821883c10c4b9a4ff2beae227bef94bcab');
const PARAMS: ProvingParams = { gLagrange: G_LAGRANGE, w: W, n: 16, blindingFactors: 5 };

// First 64 bytes of TOY_PROOF = the two advice-column commitments.
const PROOF_PREFIX = bytes(
  'f8763c53f94b473b5bd5aa3f7197df7393e85d65f3627b08ca5427adc07e8eb0' +
    '8d61ec9090e7aa4cf8160f15af580689992a636e8d2d949e00d4558b2954e192',
);
const VK_REPR = leHex('5a0e7ae13630d950ce60bc0337411b08fcb39821dd87a8dab457d68f1f28f801');
const INSTANCE_COMMIT = pt('4b2ec5a46047f25d719f122db4b8500023ede2278411fd95f9648f57c3af3999');
const THETA = leHex('32b40811b2b9b6419f2445399625f2166b379611590ef97f277b56f766c76c22');
const BETA = leHex('3c0dd97732ec84447cff2b9ec23ea48c316db2a15d38405a700b5648bdcd2721');
const GAMMA = leHex('6d25090216970a9a3d0ce0be54189db46e6bdd27428b5327e4fd564015a7d206');

describe('TS halo2 prover (create_proof) — step by step vs halo2', () => {
  it('step 1: advice commit matches the toy proof commitments', () => {
    const { commitments } = commitAdvice(PARAMS, [[3n, 15n], [5n]], new CounterRng());
    expect(hex(Vesta.toBytes(commitments[0]))).toBe(hex(PROOF_PREFIX.subarray(0, 32)));
    expect(hex(Vesta.toBytes(commitments[1]))).toBe(hex(PROOF_PREFIX.subarray(32, 64)));
  });

  it('step 2-3: transcript → theta, beta, gamma match halo2', () => {
    const { commitments } = commitAdvice(PARAMS, [[3n, 15n], [5n]], new CounterRng());
    const t = new Transcript();
    t.commonScalar(VK_REPR);
    t.commonPoint(INSTANCE_COMMIT);
    t.commonPoint(commitments[0]!);
    t.commonPoint(commitments[1]!);
    expect(t.squeezeChallenge()).toBe(THETA);
    expect(t.squeezeChallenge()).toBe(BETA);
    expect(t.squeezeChallenge()).toBe(GAMMA);
  });

  it('step 4: permutation grand-product Z (3 chunks) matches halo2', () => {
    const SIGMA = perm.sigma.map(f16);
    const Z_EXPECTED = perm.z.map(f16);
    const { advice } = commitAdvice(PARAMS, [[3n, 15n], [5n]], new CounterRng());
    const instance0 = new Array<bigint>(16).fill(0n);
    instance0[0] = 15n;
    const cols = [advice[0]!, advice[1]!, instance0];

    let lastZ = 1n;
    for (let j = 0; j < 3; j++) {
      const z = permutationZ(cols[j], SIGMA[j], BETA, GAMMA, Fp.pow(DELTA, BigInt(j)), 4, lastZ);
      expect(z.map(fe)).toEqual(Z_EXPECTED[j].map(fe));
      lastZ = z[16 - (5 + 1)]; // z[n-(bf+1)]
    }
  });
});
