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
  commitPermutationZ,
  commitVanishingRandom,
  buildFoldedH,
  commitHPieces,
  DELTA,
  type ProvingParams,
} from '../src/zkpp/prover.js';
import {
  coeffToExtended,
  lagrangeToCoeff,
  extendedToCoeff,
  divideByVanishing,
  vanishingTInv,
} from '../src/zkpp/domain.js';
import perm from './fixtures/toy-perm.json';
import toyH from './fixtures/toy-h.json';

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
// Coefficient-basis generators g (params.commit), for the vanishing random poly.
const G_COEFF = [
  '45065ed079bf389758f591131095ef419310e8c708a805852b9b77bed8c7ecbd',
  'e0c0802686d3ed571f7f3399526b24460b16ace461ebda9dcfe6e5b7b298c18c',
  'd27962962ce9ed2b87ae4c95462914917a9da0295f593956c1a76adca2ebc394',
  'a74f2af0a526eb437ebb22c416a78fda0a275a2f2756115e51248f7c5a7acdac',
  'a3c70c4c2497a714ebe96b6192bf940a13a277a6a7c4152a3524988d86be181b',
  'c887e3240ff4de618fb8531a447b4f469f50a8ac35fe905da8b8e8732e527eb8',
  'b7e796477bd8c4fe4b9ef9806c39cb32ed5558ef9d8c582909779eec700e259a',
  '6787540156e67c55fba03e961d98971ccd6bf71c4edd0d80d4d7aec06f9cdb0a',
  '4733b6af89cb374ccb4cdad193a4d959d0fe97c0c383444cf66fae33bbdb63b5',
  '2793749458a1dbf7b53c91164a9d7b57f21a5075fbe003a1eb7cf8b11ff2a930',
  '1b8d3628dd3aec8824c4757698ba0509287354eee15ca61f03d9ae4664c71f0d',
  'f6d9eeaff51693a61b5d220c9e9f33e26f02fc8a21b0e803a64308d461146920',
  '7c978cde92645552a7b574636f6a9f7d8527f48e82fabafa16ce317414d9e39e',
  '100546a64730cbdd3ff9f8651f2a0f81b59d04cf0b688f019411901310700e92',
  '842bad45abe1afcefb67eb246b6e51555802335969203562922c95ef99e4fbba',
  'a370615e5b383d342f401237f6c2b72573bf10fafbd4f41c48857e4aef63cb81',
].map(pt);
const VANISHING_COMMIT = '8de5471258730a150a77f3595d32b1b00acabc76b9b13c3c1d7c1516208ad0a6';

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

  it('step 4: permutation Z grand-product + commitments match halo2', () => {
    const SIGMA = perm.sigma.map(f16);
    const Z_EXPECTED = perm.z.map(f16);
    // Z commitments = proof[64..160] (3 points).
    const Z_COMMITS = [
      '8c0da2d2f6e89fcce83b667fa43fb3c673b7d889a2b39f3e2ab89011cd1926bd',
      '383deb440586effabce4b7a2ac1b8a26eee38d127349f5a59cbbe61aa2e7f2b6',
      '612ba22fda3af65a46ab199cbeada5f6332ec22c08b11d7971e957981f452513',
    ];

    const rng = new CounterRng();
    const { advice } = commitAdvice(PARAMS, [[3n, 15n], [5n]], rng); // draws 14
    const instance0 = new Array<bigint>(16).fill(0n);
    instance0[0] = 15n;
    const cols = [advice[0]!, advice[1]!, instance0];

    const zPolys: bigint[][] = [];
    let lastZ = 1n;
    for (let j = 0; j < 3; j++) {
      const z = permutationZ(cols[j], SIGMA[j], BETA, GAMMA, Fp.pow(DELTA, BigInt(j)), 4, lastZ);
      expect(z.map(fe)).toEqual(Z_EXPECTED[j].map(fe));
      zPolys.push(z);
      lastZ = z[16 - (5 + 1)]; // z[n-(bf+1)]
    }
    // Commit each Z (blinding rows + blind continue the same RNG).
    const { commitments: commits } = commitPermutationZ(PARAMS, zPolys, rng);
    commits.forEach((c, i) => expect(hex(Vesta.toBytes(c))).toBe(Z_COMMITS[i]));
  });

  it('step 5: y challenge (absorb Z commitments) matches halo2', () => {
    const Y = leHex('aa5e2e0c3f992b8a7b60a98a0f6697d624cdb1e5ad9cc89433bdbb8bfd15b41b');
    const SIGMA = perm.sigma.map(f16);
    const rng = new CounterRng();
    const { commitments: adviceCommits, advice } = commitAdvice(PARAMS, [[3n, 15n], [5n]], rng);
    const instance0 = new Array<bigint>(16).fill(0n);
    instance0[0] = 15n;
    const cols = [advice[0]!, advice[1]!, instance0];
    const zPolys: bigint[][] = [];
    let lastZ = 1n;
    for (let j = 0; j < 3; j++) {
      const z = permutationZ(cols[j], SIGMA[j], BETA, GAMMA, Fp.pow(DELTA, BigInt(j)), 4, lastZ);
      zPolys.push(z);
      lastZ = z[10];
    }
    const { commitments: zCommits } = commitPermutationZ(PARAMS, zPolys, rng);
    // Vanishing random blinding commitment (coeff basis) — absorbed before y.
    const vanishingCommit = commitVanishingRandom(G_COEFF, W, 16, rng);
    expect(hex(Vesta.toBytes(vanishingCommit))).toBe(VANISHING_COMMIT);

    const t = new Transcript();
    t.commonScalar(VK_REPR);
    t.commonPoint(INSTANCE_COMMIT);
    t.commonPoint(adviceCommits[0]!);
    t.commonPoint(adviceCommits[1]!);
    t.squeezeChallenge(); // theta
    t.squeezeChallenge(); // beta
    t.squeezeChallenge(); // gamma
    for (const c of zCommits) t.commonPoint(c);
    t.commonPoint(vanishingCommit);
    expect(t.squeezeChallenge()).toBe(Y); // vanishing challenge
  });

  it('step 6a: advice extended coset = coeffToExtended(lagrangeToCoeff(advice))', () => {
    const f32 = (h: string) =>
      Array.from({ length: 32 }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const { advice } = commitAdvice(PARAMS, [[3n, 15n], [5n]], new CounterRng());
    const coset0 = coeffToExtended(lagrangeToCoeff(advice[0]!, 4), 5);
    const coset1 = coeffToExtended(lagrangeToCoeff(advice[1]!, 4), 5);
    expect(coset0.map(fe)).toEqual(f32(toyH.adv_coset_0).map(fe));
    expect(coset1.map(fe)).toEqual(f32(toyH.adv_coset_1).map(fe));
  });

  it('step 6b: folded H (gate + permutation constraints, y-folded) matches halo2', () => {
    const f32 = (h: string) =>
      Array.from({ length: 32 }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const Y = leHex('aa5e2e0c3f992b8a7b60a98a0f6697d624cdb1e5ad9cc89433bdbb8bfd15b41b');
    const SIGMA = perm.sigma.map(f16);
    const rng = new CounterRng();
    const { advice } = commitAdvice(PARAMS, [[3n, 15n], [5n]], rng);
    const instance0 = new Array<bigint>(16).fill(0n);
    instance0[0] = 15n;
    const cols = [advice[0]!, advice[1]!, instance0];
    const zPolys: bigint[][] = [];
    let lastZ = 1n;
    for (let j = 0; j < 3; j++) {
      const z = permutationZ(cols[j], SIGMA[j], BETA, GAMMA, Fp.pow(DELTA, BigInt(j)), 4, lastZ);
      zPolys.push(z);
      lastZ = z[10];
    }
    const { blindedZ } = commitPermutationZ(PARAMS, zPolys, rng);
    const toCoset = (lag: bigint[]) => coeffToExtended(lagrangeToCoeff(lag, 4), 5);
    const H = buildFoldedH(
      {
        adv0: toCoset(advice[0]!),
        adv1: toCoset(advice[1]!),
        inst: toCoset(instance0),
        sel: f32(toyH.fixed_coset_0),
        z: blindedZ.map(toCoset),
        sigma: SIGMA.map(toCoset),
        l0: f32(toyH.l0),
        lLast: f32(toyH.l_last),
        lBlind: f32(toyH.l_blind),
      },
      BETA,
      GAMMA,
      Y,
      4,
      5,
      5,
    );
    expect(H.map(fe)).toEqual(f32(toyH.h_folded).map(fe));
  });

  it('step 6c-7: h-pieces commit (proof[192..256]) + x challenge match halo2', () => {
    const f32 = (h: string) => Array.from({ length: 32 }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const Y = leHex('aa5e2e0c3f992b8a7b60a98a0f6697d624cdb1e5ad9cc89433bdbb8bfd15b41b');
    const X_EXP = leHex('8f9a7d0585b6ac4219645b208fa168aa5352e3a2bed204fb0c3a2c005fd5130e');
    const H_COMMITS = [
      'f92f44fafe9d25a9b56214e4169cf35af04fce6b2a23c951459ad352931939a9',
      '1bfc6a4422b30d01aabb604949d1348b186b5fd65262f9add1389a2639ad2c30',
    ];
    const SIGMA = perm.sigma.map(f16);
    const rng = new CounterRng();
    const { commitments: adviceCommits, advice } = commitAdvice(PARAMS, [[3n, 15n], [5n]], rng);
    const instance0 = new Array<bigint>(16).fill(0n);
    instance0[0] = 15n;
    const cols = [advice[0]!, advice[1]!, instance0];
    const zPolys: bigint[][] = [];
    let lastZ = 1n;
    for (let j = 0; j < 3; j++) {
      const z = permutationZ(cols[j], SIGMA[j], BETA, GAMMA, Fp.pow(DELTA, BigInt(j)), 4, lastZ);
      zPolys.push(z);
      lastZ = z[10];
    }
    const { commitments: zCommits, blindedZ } = commitPermutationZ(PARAMS, zPolys, rng);
    const vanishingCommit = commitVanishingRandom(G_COEFF, W, 16, rng);
    // Quotient h(X): folded constraints / t(X), back to coefficients.
    const toCoset = (lag: bigint[]) => coeffToExtended(lagrangeToCoeff(lag, 4), 5);
    const folded = buildFoldedH(
      {
        adv0: toCoset(advice[0]!),
        adv1: toCoset(advice[1]!),
        inst: toCoset(instance0),
        sel: f32(toyH.fixed_coset_0),
        z: blindedZ.map(toCoset),
        sigma: SIGMA.map(toCoset),
        l0: f32(toyH.l0),
        lLast: f32(toyH.l_last),
        lBlind: f32(toyH.l_blind),
      },
      BETA,
      GAMMA,
      Y,
      4,
      5,
      5,
    );
    const hPoly = extendedToCoeff(divideByVanishing(folded, vanishingTInv(4, 5)), 4, 5, 2);
    const hCommits = commitHPieces(G_COEFF, W, hPoly, 16, rng);
    hCommits.forEach((c, i) => expect(hex(Vesta.toBytes(c))).toBe(H_COMMITS[i]));

    // Transcript through y, absorb h commitments, squeeze x.
    const t = new Transcript();
    t.commonScalar(VK_REPR);
    t.commonPoint(INSTANCE_COMMIT);
    t.commonPoint(adviceCommits[0]!);
    t.commonPoint(adviceCommits[1]!);
    t.squeezeChallenge();
    t.squeezeChallenge();
    t.squeezeChallenge();
    for (const c of zCommits) t.commonPoint(c);
    t.commonPoint(vanishingCommit);
    t.squeezeChallenge(); // y
    for (const c of hCommits) t.commonPoint(c);
    expect(t.squeezeChallenge()).toBe(X_EXP);
  });
});
