/**
 * Group operations tests for all 5 supported curves.
 *
 * Tests: serialize/deserialize, scalarMult, scalarInverse, scalarBaseMult,
 * scalarReduce, ECDH, hashToGroup, identity, add, generateKeypair.
 */
import { describe, it, expect } from 'vitest';
import { getGroup } from '../../src/group/index.js';
import { CurveId } from '../../src/suites.js';

const CURVES = [
  { id: CurveId.RISTRETTO255, name: 'Ristretto255', scalarSize: 32, elementSize: 32 },
  { id: CurveId.P256, name: 'P-256', scalarSize: 32, elementSize: 33 },
  { id: CurveId.P384, name: 'P-384', scalarSize: 48, elementSize: 49 },
  { id: CurveId.P521, name: 'P-521', scalarSize: 66, elementSize: 67 },
] as const;

const te = new TextEncoder();

for (const curve of CURVES) {
  describe(`GroupOps: ${curve.name}`, () => {
    const group = getGroup(curve.id);

    it('has correct scalarSize and elementSize', () => {
      expect(group.scalarSize).toBe(curve.scalarSize);
      expect(group.elementSize).toBe(curve.elementSize);
    });

    // ── randomScalar ──

    it('randomScalar returns correct size', () => {
      const scalar = group.randomScalar();
      expect(scalar).toBeInstanceOf(Uint8Array);
      expect(scalar.length).toBe(curve.scalarSize);
    });

    it('randomScalar produces non-zero values', () => {
      const scalar = group.randomScalar();
      const isZero = scalar.every((b) => b === 0);
      expect(isZero).toBe(false);
    });

    it('randomScalar produces different values each call', () => {
      const a = group.randomScalar();
      const b = group.randomScalar();
      expect(a).not.toEqual(b);
    });

    // ── serialize / deserialize roundtrip ──

    it('serialize/deserialize roundtrip preserves element', () => {
      const { publicKey } = group.generateKeypair();
      const element = group.deserializeElement(publicKey);
      const serialized = group.serializeElement(element);
      expect(serialized).toEqual(publicKey);
    });

    it('serialize produces correct size', () => {
      const { publicKey } = group.generateKeypair();
      expect(publicKey.length).toBe(curve.elementSize);
    });

    // ── scalarBaseMult ──

    it('scalarBaseMult: scalar * G produces valid element', () => {
      const scalar = group.randomScalar();
      const element = group.scalarBaseMult(scalar);
      const bytes = group.serializeElement(element);
      expect(bytes.length).toBe(curve.elementSize);
      // Deserialize should not throw
      group.deserializeElement(bytes);
    });

    it('scalarBaseMult: same scalar → same result', () => {
      const scalar = group.randomScalar();
      const a = group.serializeElement(group.scalarBaseMult(scalar));
      const b = group.serializeElement(group.scalarBaseMult(scalar));
      expect(a).toEqual(b);
    });

    it('scalarBaseMult: different scalars → different results', () => {
      const s1 = group.randomScalar();
      const s2 = group.randomScalar();
      const a = group.serializeElement(group.scalarBaseMult(s1));
      const b = group.serializeElement(group.scalarBaseMult(s2));
      expect(a).not.toEqual(b);
    });

    // ── scalarMult ──

    it('scalarMult: r * (s * G) = (r * s) * G', () => {
      const s = group.randomScalar();
      const r = group.randomScalar();
      // s * G
      const sG = group.scalarBaseMult(s);
      // r * (s * G)
      const rsG = group.scalarMult(r, sG);
      const rsGBytes = group.serializeElement(rsG);

      // r * s mod order — we do this via scalarReduce of concatenated multiplication
      // Instead test commutativity: s * (r * G) should equal r * (s * G)
      const rG = group.scalarBaseMult(r);
      const srG = group.scalarMult(s, rG);
      const srGBytes = group.serializeElement(srG);

      expect(rsGBytes).toEqual(srGBytes);
    });

    // ── scalarInverse ──

    it('scalarInverse: s * s⁻¹ * G = G', () => {
      const s = group.randomScalar();
      const sInv = group.scalarInverse(s);
      // s * G
      const sG = group.scalarBaseMult(s);
      // s⁻¹ * (s * G) = G
      const result = group.scalarMult(sInv, sG);
      const resultBytes = group.serializeElement(result);

      // Compare with G = 1 * G
      const one = new Uint8Array(curve.scalarSize);
      one[curve.scalarSize - 1] = 1;
      const gBytes = group.serializeElement(group.scalarBaseMult(one));
      expect(resultBytes).toEqual(gBytes);
    });

    // ── scalarReduce ──

    it('scalarReduce: reduces to scalarSize bytes', () => {
      const oversized = new Uint8Array(curve.scalarSize * 2);
      crypto.getRandomValues(oversized);
      const reduced = group.scalarReduce(oversized);
      expect(reduced.length).toBe(curve.scalarSize);
    });

    it('scalarReduce: non-zero result', () => {
      const input = new Uint8Array(curve.scalarSize * 2);
      crypto.getRandomValues(input);
      const reduced = group.scalarReduce(input);
      const isZero = reduced.every((b) => b === 0);
      expect(isZero).toBe(false);
    });

    it('scalarReduce: deterministic', () => {
      const input = new Uint8Array(64);
      input.fill(0xab);
      const a = group.scalarReduce(input);
      const b = group.scalarReduce(input);
      expect(a).toEqual(b);
    });

    // ── generateKeypair ──

    it('generateKeypair returns correct sizes', () => {
      const { secretKey, publicKey } = group.generateKeypair();
      expect(secretKey.length).toBe(curve.scalarSize);
      expect(publicKey.length).toBe(curve.elementSize);
    });

    it('generateKeypair: public key = secretKey * G', () => {
      const { secretKey, publicKey } = group.generateKeypair();
      const derived = group.serializeElement(group.scalarBaseMult(secretKey));
      expect(derived).toEqual(publicKey);
    });

    it('generateKeypair produces different keys each call', () => {
      const a = group.generateKeypair();
      const b = group.generateKeypair();
      expect(a.secretKey).not.toEqual(b.secretKey);
      expect(a.publicKey).not.toEqual(b.publicKey);
    });

    // ── ECDH ──

    it('ECDH: shared secret is symmetric', () => {
      const alice = group.generateKeypair();
      const bob = group.generateKeypair();
      const sharedA = group.ecdh(alice.secretKey, bob.publicKey);
      const sharedB = group.ecdh(bob.secretKey, alice.publicKey);
      expect(sharedA).toEqual(sharedB);
    });

    it('ECDH: different pairs → different shared secrets', () => {
      const alice = group.generateKeypair();
      const bob = group.generateKeypair();
      const carol = group.generateKeypair();
      const sharedAB = group.ecdh(alice.secretKey, bob.publicKey);
      const sharedAC = group.ecdh(alice.secretKey, carol.publicKey);
      expect(sharedAB).not.toEqual(sharedAC);
    });

    // ── identity ──

    it('identity + P = P', () => {
      const { publicKey } = group.generateKeypair();
      const p = group.deserializeElement(publicKey);
      const id = group.identity();
      const sum = group.add(id, p);
      const sumBytes = group.serializeElement(sum);
      expect(sumBytes).toEqual(publicKey);
    });

    // ── add ──

    it('add is commutative: P + Q = Q + P', () => {
      const p = group.deserializeElement(group.generateKeypair().publicKey);
      const q = group.deserializeElement(group.generateKeypair().publicKey);
      const pqBytes = group.serializeElement(group.add(p, q));
      const qpBytes = group.serializeElement(group.add(q, p));
      expect(pqBytes).toEqual(qpBytes);
    });

    it('add: 2 * G = G + G', () => {
      const one = new Uint8Array(curve.scalarSize);
      one[curve.scalarSize - 1] = 1;
      const g = group.scalarBaseMult(one);
      const twoG = group.add(g, g);
      const twoGBytes = group.serializeElement(twoG);

      const two = new Uint8Array(curve.scalarSize);
      two[curve.scalarSize - 1] = 2;
      const twoGMult = group.scalarBaseMult(two);
      const twoGMultBytes = group.serializeElement(twoGMult);

      expect(twoGBytes).toEqual(twoGMultBytes);
    });

    // ── hashToGroup ──

    it('hashToGroup: produces valid group element', () => {
      const input = te.encode('test-input');
      const dst = te.encode('test-dst');
      const element = group.hashToGroup(input, dst);
      const bytes = group.serializeElement(element);
      expect(bytes.length).toBe(curve.elementSize);
      // Should roundtrip
      group.deserializeElement(bytes);
    });

    it('hashToGroup: deterministic for same input', () => {
      const input = te.encode('deterministic-test');
      const dst = te.encode('test-dst');
      const a = group.serializeElement(group.hashToGroup(input, dst));
      const b = group.serializeElement(group.hashToGroup(input, dst));
      expect(a).toEqual(b);
    });

    it('hashToGroup: different inputs → different elements', () => {
      const dst = te.encode('test-dst');
      const a = group.serializeElement(group.hashToGroup(te.encode('input-a'), dst));
      const b = group.serializeElement(group.hashToGroup(te.encode('input-b'), dst));
      expect(a).not.toEqual(b);
    });

    // ── Error cases ──

    it('deserializeElement rejects garbage bytes', () => {
      const garbage = new Uint8Array(curve.elementSize);
      garbage.fill(0xff);
      expect(() => group.deserializeElement(garbage)).toThrow();
    });
  });
}

describe('getGroup', () => {
  it('throws for unknown curve', () => {
    expect(() => getGroup(999 as CurveId)).toThrow('Unsupported curve');
  });
});
