// TS prover step 1 (advice commit) interop vs halo2 create_proof. Toy circuit
// a·b=c (3·5=15), k=4, deterministic counter RNG. Vectors from toy_proof.rs.
import { describe, it, expect } from 'vitest';
import { Vesta } from '../src/zkpp/curve.js';
import { CounterRng, commitAdvice, type ProvingParams } from '../src/zkpp/prover.js';

const bytes = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const pt = (h: string) => Vesta.fromBytes(bytes(h)) as { x: bigint; y: bigint };

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

// First 64 bytes of TOY_PROOF = the two advice-column commitments.
const PROOF_PREFIX = bytes(
  'f8763c53f94b473b5bd5aa3f7197df7393e85d65f3627b08ca5427adc07e8eb0' +
    '8d61ec9090e7aa4cf8160f15af580689992a636e8d2d949e00d4558b2954e192',
);

describe('TS halo2 prover — advice commit (create_proof step 1)', () => {
  it('commitAdvice([[3,15],[5]]) matches the toy proof commitments', () => {
    const params: ProvingParams = { gLagrange: G_LAGRANGE, w: W, n: 16, blindingFactors: 5 };
    // advice[0] = [a=3, out=15], advice[1] = [b=5]; rest zero + blinding rows.
    const { commitments } = commitAdvice(params, [[3n, 15n], [5n]], new CounterRng());
    expect(hex(Vesta.toBytes(commitments[0]))).toBe(hex(PROOF_PREFIX.subarray(0, 32)));
    expect(hex(Vesta.toBytes(commitments[1]))).toBe(hex(PROOF_PREFIX.subarray(32, 64)));
  });
});
