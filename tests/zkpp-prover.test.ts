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
  evalPolynomial,
  buildIPA,
  buildMultiopen,
  permuteExpressionPair,
  commitLookupProduct,
  buildLookupExpressions,
  DELTA,
  type ProvingParams,
} from '../src/zkpp/prover.js';
import lookup from './fixtures/toy-lookup.json';
import { omegaForSize } from '../src/zkpp/fft.js';
import ipa from './fixtures/toy-ipa.json';
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
    const { commitment: vanishingCommit } = commitVanishingRandom(G_COEFF, W, 16, rng);
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
    const f32 = (h: string) =>
      Array.from({ length: 32 }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
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
    const { commitment: vanishingCommit } = commitVanishingRandom(G_COEFF, W, 16, rng);
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

  it('step 8: evaluations at x (proof[256..800]) match halo2', () => {
    const f32 = (h: string) =>
      Array.from({ length: 32 }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const X = leHex('8f9a7d0585b6ac4219645b208fa168aa5352e3a2bed204fb0c3a2c005fd5130e');
    // proof[256..800] = 17 evaluation scalars.
    const EVALS =
      '50452872347baf0d17f9293a6fdf60ecba8a8396865dec96bc56bcb0be2c9b100179b165f923177088752c1ab8cd00509fdf05d1b328cd1faa4d294ed6ae990cab84131ff6f23467f57b1bd89313412b78f72e90dd83cafaf7fee7e657ce3b28e48b225f4e50350276d368bb51a34d66725a820e4e0ca50d9b0f2bcd47c64922288de04be8bb12ca98b7093cf4d7e7ff834d9192a26cbab42e6cea2d848b3d23d896e7c6a57116c1ea68a6bd19b359f523cf2888773de8d60eb2fc019824a91eaa94002a1d9a36f228634d7d531280c8960f6c97cabd4990033be0c8ced4863890b369343bcfac70b4288f64b220d46e0b9590e220fb88d62d8c436f6387ae14289fcb232b27a24fdadf96b2cff688437a8e94bd4fdf0f94accbe32eeef5ed286dfda276b9bb6edabbf31d820a1d95f5e05701fc9ee92cfcb05e6dc311d6d43e4d2502cf26c250ccb89f8f16d3abd35873091804a86ee4bb24a0c3c7343ffd1daefb366682b350a04b906ee73407edbd97c55c57039d811d552874c76a25d916de5199c9cbb68cf608c61c328b85a48d4511d077d3908e63b804843b3c80951a1375e9a73a06a87efc87c2727885135bb630c3dd7729c8b2bb8eec1fb0bfc82ac8447b70bd78689312e159bbefbd0cd51058fa1b379f8c186e2f5c651005a02b85e3dc87c6a983d2888f9411fb151f87b4d78a7cb4a959f488bc311c4d28131fd4322a2614d88a48dad0b19333f38b42447793c407910ee5526e4c6a6f8ff037';
    const expected = Array.from({ length: 17 }, (_, i) =>
      leHex(EVALS.slice(i * 64, i * 64 + 64)),
    ).map(fe);

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
    const { randomPoly } = commitVanishingRandom(G_COEFF, W, 16, rng);

    const adv0c = lagrangeToCoeff(advice[0]!, 4);
    const adv1c = lagrangeToCoeff(advice[1]!, 4);
    const instc = lagrangeToCoeff(instance0, 4);
    const selc = extendedToCoeff(f32(toyH.fixed_coset_0), 4, 5, 2).slice(0, 16);
    const zc = blindedZ.map((z) => lagrangeToCoeff(z, 4));
    const sigc = SIGMA.map((s) => lagrangeToCoeff(s, 4));

    const omega = omegaForSize(4);
    const xw = Fp.mul(X, omega); // rotate next
    const xLast = Fp.mul(X, Fp.pow(omega, 10n)); // rotate -(bf+1) = -6 ≡ +10

    const evals: bigint[] = [];
    evals.push(evalPolynomial(instc, X)); // instance query 0:0
    evals.push(evalPolynomial(adv0c, X), evalPolynomial(adv1c, X), evalPolynomial(adv0c, xw)); // advice
    evals.push(evalPolynomial(selc, X)); // fixed 0:0
    evals.push(evalPolynomial(randomPoly, X)); // vanishing random
    for (let i = 0; i < 3; i++) evals.push(evalPolynomial(sigc[i], X)); // permutation common (σ)
    for (let s = 0; s < 3; s++) {
      evals.push(evalPolynomial(zc[s], X), evalPolynomial(zc[s], xw));
      if (s < 2) evals.push(evalPolynomial(zc[s], xLast));
    }
    expect(evals.map(fe)).toEqual(expected);
  });

  it('step 9a: IPA opening (s_commit, L/R, c, f) matches halo2', () => {
    const f16c = (h: string) =>
      Array.from({ length: 16 }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const pPoly = f16c(ipa.ppoly);
    const pBlind = leHex(ipa.pblind);
    const x3 = leHex(ipa.x3);
    const xi = leHex(ipa.ipa_xi);
    const z = leHex(ipa.ipa_z);
    const U = pt(ipa.ipa_u);
    const uChals = [
      'b15f4ee0cce35028b37af707eb8cefd776ffc1acd604abd0a23cd37331f14124',
      '4d3aabab2f303901c3fe70dcd7756016820caa83d0f95ba07fc6c004809b1501',
      'e5861f62bb28f4c2dc42c8314a88c0ce0cb13e3014724d8fa010cf52158f7224',
      '2219973eb73a35339de76ac5b6fc7a13692e45f14e2b901822e496be38b43e01',
    ].map(leHex);
    const tail = bytes(ipa.proof_tail); // proof[800..1280]

    // Position the RNG at the IPA's s_poly draw: 52 prior draws (advice 14 +
    // permutation 18 + vanishing-random 17 + h-pieces 2 + q_prime_blind 1).
    const rng = new CounterRng();
    for (let i = 0; i < 52; i++) rng.nextScalar();

    const { sCommit, lr, c, f } = buildIPA(pPoly, pBlind, x3, G_COEFF, W, U, xi, z, uChals, rng, 4);
    expect(hex(Vesta.toBytes(sCommit))).toBe(hex(tail.subarray(128, 160)));
    for (let j = 0; j < 4; j++) {
      expect(hex(Vesta.toBytes(lr[j][0]))).toBe(
        hex(tail.subarray(160 + j * 64, 160 + j * 64 + 32)),
      );
      expect(hex(Vesta.toBytes(lr[j][1]))).toBe(
        hex(tail.subarray(160 + j * 64 + 32, 160 + j * 64 + 64)),
      );
    }
    expect(fe(c)).toBe(hex(tail.subarray(416, 448)));
    expect(fe(f)).toBe(hex(tail.subarray(448, 480)));
  });

  it('step 9b: multiopen (q_prime, q_evals, p_poly) matches halo2 → full proof', () => {
    const f32 = (h: string) =>
      Array.from({ length: 32 }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const f16c = (h: string) =>
      Array.from({ length: 16 }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const X = leHex('8f9a7d0585b6ac4219645b208fa168aa5352e3a2bed204fb0c3a2c005fd5130e');
    const Y = leHex('aa5e2e0c3f992b8a7b60a98a0f6697d624cdb1e5ad9cc89433bdbb8bfd15b41b');
    const x1 = leHex(ipa.x1);
    const x2 = leHex(ipa.x2);
    const x3 = leHex(ipa.x3);
    const x4 = leHex(ipa.x4);
    const tail = bytes(ipa.proof_tail);

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
    const { randomPoly } = commitVanishingRandom(G_COEFF, W, 16, rng);
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

    // Coefficient polynomials opened by the multiopen.
    const inst0c = lagrangeToCoeff(instance0, 4);
    const adv0c = lagrangeToCoeff(advice[0]!, 4);
    const adv1c = lagrangeToCoeff(advice[1]!, 4);
    const selc = extendedToCoeff(f32(toyH.fixed_coset_0), 4, 5, 2).slice(0, 16);
    const sigc = SIGMA.map((s) => lagrangeToCoeff(s, 4));
    const zc = blindedZ.map((z) => lagrangeToCoeff(z, 4));
    const xn = Fp.pow(X, 16n);
    const hComb = hPoly.slice(0, 16).map((v, i) => Fp.add(v, Fp.mul(hPoly[16 + i], xn)));

    const omega = omegaForSize(4);
    const Xw = Fp.mul(X, omega);
    const Xlast = Fp.mul(X, Fp.pow(omega, 10n));

    // Three point sets in first-occurrence order (npointsets=3).
    const sets = [
      { polys: [inst0c, adv1c, selc, sigc[0], sigc[1], sigc[2], hComb, randomPoly], points: [X] },
      { polys: [adv0c, zc[2]], points: [X, Xw] },
      { polys: [zc[0], zc[1]], points: [X, Xw, Xlast] },
    ];
    const { qPrime, qEvals, pPoly } = buildMultiopen(sets, x1, x2, x3, x4, 16);

    // p(X) feeding the IPA must equal halo2's p_poly (ties multiopen → IPA).
    expect(pPoly.map(fe)).toEqual(f16c(ipa.ppoly).map(fe));
    // q evals = proof[832..928] (3 scalars).
    for (let i = 0; i < 3; i++)
      expect(fe(qEvals[i])).toBe(hex(tail.subarray(32 + i * 32, 32 + i * 32 + 32)));
    // q_prime commitment = proof[800..832]; blind = RNG draw 51.
    const rng2 = new CounterRng();
    for (let i = 0; i < 51; i++) rng2.nextScalar();
    const qpBlind = rng2.nextScalar();
    const qpCommit = Vesta.add(Vesta.msm(qPrime, G_COEFF), Vesta.scalarMul(qpBlind, W));
    expect(hex(Vesta.toBytes(qpCommit))).toBe(hex(tail.subarray(0, 32)));
  });

  it('lookup: permute A\'/S\' + commitments match halo2', () => {
    const cin = f16(lookup.cin);
    const ctab = f16(lookup.ctab);
    const AP = f16(lookup.ap);
    const SP = f16(lookup.sp);
    // Lookup toy uses the same params (k=4), so g_lagrange/w match the mul toy.
    const rng = new CounterRng();
    for (let i = 0; i < 7; i++) rng.nextScalar(); // skip advice (1 col: 6 blinding rows + 1 blind)
    const { pInput, pTable } = permuteExpressionPair(cin, ctab, 10, 5, rng);
    expect(pInput.map(fe)).toEqual(AP.map(fe));
    expect(pTable.map(fe)).toEqual(SP.map(fe));
    const apBlind = rng.nextScalar();
    const spBlind = rng.nextScalar();
    const apCommit = Vesta.add(Vesta.msm(pInput, G_LAGRANGE), Vesta.scalarMul(apBlind, W));
    const spCommit = Vesta.add(Vesta.msm(pTable, G_LAGRANGE), Vesta.scalarMul(spBlind, W));
    expect(hex(Vesta.toBytes(apCommit))).toBe(lookup.ap_commit);
    expect(hex(Vesta.toBytes(spCommit))).toBe(lookup.sp_commit);
  });

  it('lookup: commit_product Z_lookup matches halo2', () => {
    const cin = f16(lookup.cin);
    const ctab = f16(lookup.ctab);
    const ap = f16(lookup.ap);
    const sp = f16(lookup.sp);
    const beta = leHex('c772e4ea6b2cb41ac32909d61150629b7365b6d6c4e86bd703531ccbfa244424');
    const gamma = leHex('3e166b0d82ecddeed5b97ea5915f1845dff2b884b4f31d2571e012be1fe0b038');
    const rng = new CounterRng();
    for (let i = 0; i < 21; i++) rng.nextScalar(); // advice 7 + permute 12 + A'/S' commits 2
    const { commitment } = commitLookupProduct(cin, ctab, ap, sp, beta, gamma, PARAMS, rng);
    expect(hex(Vesta.toBytes(commitment))).toBe(
      '1aea09b2473ee27e9fa568cf7dce10912aad4b8fa188da76fd01ad6d7f1997bb',
    );
  });

  it('lookup: folded H (gate + lookup expressions) matches halo2', () => {
    const f64 = (h: string) => Array.from({ length: 64 }, (_, i) => leHex(h.slice(i * 64, i * 64 + 64)));
    const cin = f16(lookup.cin);
    const ctab = f16(lookup.ctab);
    const beta = leHex(lookup.beta);
    const gamma = leHex(lookup.gamma);
    const Y = leHex(lookup.y);
    const rng = new CounterRng();
    for (let i = 0; i < 7; i++) rng.nextScalar(); // advice
    const { pInput, pTable } = permuteExpressionPair(cin, ctab, 10, 5, rng); // permute (12)
    rng.nextScalar(); // A' commit blind
    rng.nextScalar(); // S' commit blind
    const { zPoly } = commitLookupProduct(cin, ctab, pInput, pTable, beta, gamma, PARAMS, rng);
    const toCoset6 = (lag: bigint[]) => coeffToExtended(lagrangeToCoeff(lag, 4), 6);
    const exprs = buildLookupExpressions(
      {
        z: toCoset6(zPoly),
        ap: toCoset6(pInput),
        sp: toCoset6(pTable),
        cin: toCoset6(cin),
        ctab: toCoset6(ctab),
        l0: f64(lookup.l0),
        lLast: f64(lookup.llast),
        lBlind: f64(lookup.lblind),
      },
      beta,
      gamma,
      4,
      6,
    );
    // expressions = [gate(noop=0), ...5 lookup]; folded by Horner with y.
    const all = [new Array<bigint>(64).fill(0n), ...exprs];
    const H = new Array<bigint>(64).fill(0n);
    for (const e of all) for (let i = 0; i < 64; i++) H[i] = Fp.add(Fp.mul(H[i], Y), e[i]);
    expect(H.map(fe)).toEqual(f64(lookup.hfolded).map(fe));
  });

  it('lookup: evals (product, A\', S\') match halo2', () => {
    const cin = f16(lookup.cin);
    const ctab = f16(lookup.ctab);
    const beta = leHex(lookup.beta);
    const gamma = leHex(lookup.gamma);
    const X = leHex(lookup.x);
    const rng = new CounterRng();
    for (let i = 0; i < 7; i++) rng.nextScalar();
    const { pInput, pTable } = permuteExpressionPair(cin, ctab, 10, 5, rng);
    rng.nextScalar();
    rng.nextScalar();
    const { zPoly } = commitLookupProduct(cin, ctab, pInput, pTable, beta, gamma, PARAMS, rng);
    const zc = lagrangeToCoeff(zPoly, 4);
    const apc = lagrangeToCoeff(pInput, 4);
    const spc = lagrangeToCoeff(pTable, 4);
    const omega = omegaForSize(4);
    const xw = Fp.mul(X, omega);
    const xinv = Fp.mul(X, Fp.pow(omega, 15n));
    const evals = [
      evalPolynomial(zc, X),
      evalPolynomial(zc, xw),
      evalPolynomial(apc, X),
      evalPolynomial(apc, xinv),
      evalPolynomial(spc, X),
    ];
    const proof = bytes(lookup.proof);
    for (let i = 0; i < 5; i++) {
      expect(fe(evals[i])).toBe(hex(proof.subarray(384 + i * 32, 384 + i * 32 + 32)));
    }
  });
});
