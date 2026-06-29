// IPA commitment interop vs halo2 Params::commit. Vectors from interop_vectors.rs
// (dump_ipa): g[]/w recovered via commit of unit/zero polynomials, k=2 (n=4).
import { describe, it, expect } from 'vitest';
import { Vesta } from '../src/curve.js';
import { ipaCommit, type IpaParams } from '../src/ipa.js';

const bytes = (h: string): Uint8Array =>
  new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const pt = (h: string) => Vesta.fromBytes(bytes(h)) as { x: bigint; y: bigint };

const params: IpaParams = {
  g: [
    pt('45065ed079bf389758f591131095ef419310e8c708a805852b9b77bed8c7ecbd'),
    pt('e0c0802686d3ed571f7f3399526b24460b16ace461ebda9dcfe6e5b7b298c18c'),
    pt('d27962962ce9ed2b87ae4c95462914917a9da0295f593956c1a76adca2ebc394'),
    pt('a74f2af0a526eb437ebb22c416a78fda0a275a2f2756115e51248f7c5a7acdac'),
  ],
  w: pt('7520d96f3e5cd41760367151608b54821883c10c4b9a4ff2beae227bef94bcab'),
};
const IPA_COMMIT_1234_b7 = 'dea0094c5be1c9eb7a73f5ed7d37b388d29c3b7e9eed6efbf1d26ef8a5c768b2';

describe('IPA commitment — halo2 Params::commit interop', () => {
  it('commit([1,2,3,4], blind=7) matches Rust', () => {
    const c = ipaCommit(params, [1n, 2n, 3n, 4n], 7n);
    expect(hex(Vesta.toBytes(c))).toBe(IPA_COMMIT_1234_b7);
  });

  it('commit(e_i, 0) recovers generator g[i]', () => {
    for (let i = 0; i < 4; i++) {
      const e = [0n, 0n, 0n, 0n];
      e[i] = 1n;
      expect(hex(Vesta.toBytes(ipaCommit(params, e, 0n)))).toBe(hex(Vesta.toBytes(params.g[i])));
    }
  });
});
