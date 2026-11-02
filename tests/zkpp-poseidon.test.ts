// Poseidon (P128Pow5T3) interop vs sid_pake_core::poseidon. Vectors from
// interop_vectors.rs (dump_poseidon).
import { describe, it, expect } from "vitest";
import { Fp } from "../src/field.js";
import {
  poseidonHash2,
  poseidonHash1,
  passwordHash,
  bytesToFieldElements,
} from "../src/poseidon.js";
import { hashToGroup } from "../src/opaque/oprf.js";
import { historyInput } from "../src/history.js";
import { Pallas } from "../src/curve.js";

const hex = (b: Uint8Array) =>
  [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const fe = (v: bigint) => hex(Fp.toBytes(v));
const te = new TextEncoder();

describe("Poseidon P128Pow5T3 — Rust interop", () => {
  it("poseidonHash2(1, 2) matches Rust", () => {
    expect(fe(poseidonHash2(1n, 2n))).toBe(
      "4ce3bd9407dc758983c62390ce00463beb82796eb0d40a0398993cb4eca55535",
    );
  });

  it("poseidonHash1(7) matches Rust", () => {
    expect(fe(poseidonHash1(7n))).toBe(
      "c4443c01cdfc9df3d732b50c18ff55b688d1f30f264532836f2a180ca7636c0c",
    );
  });

  it('passwordHash("Str0ngP@ssword!") matches Rust', () => {
    expect(fe(passwordHash(te.encode("Str0ngP@ssword!")))).toBe(
      "41c16d0decf874c6948613891d6c3507646197b4058deede6038eeae2cb6a423",
    );
  });
});

/** One 31-byte little-endian chunk of `value`, the unit a password packs in. */
const chunk = (value: bigint) => Fp.toBytes(value).subarray(0, 31);

const point = (password: Uint8Array) =>
  hex(Pallas.toBytes(hashToGroup(password)));

// One OPRF evaluation must not answer for two passwords (RFC 9497 §4.6).
describe("the password hash keeps distinct passwords apart", () => {
  it("a trailing NUL is another password", () => {
    expect(point(te.encode("a"))).not.toBe(point(te.encode("a\0")));
    expect(historyInput(1n, te.encode("a"))).not.toBe(
      historyInput(1n, te.encode("a\0")),
    );
  });

  it("the chain over a long input does not compress", () => {
    const values = [173n, 1n, 2n, 3n, 4n, 5n];
    const head = poseidonHash2(values[0], values[1]);
    const join = (vs: bigint[]) => {
      const out = new Uint8Array(vs.length * 31);
      vs.forEach((v, i) => out.set(chunk(v), i * 31));
      return out;
    };
    const long = join(values);
    const short = join([head, ...values.slice(2)]);
    expect([long.length, short.length]).toEqual([186, 155]);
    expect(point(long)).not.toBe(point(short));
  });

  it("boundary lengths hash apart", () => {
    const lengths = [1, 30, 31, 32, 62, 127, 128, 129, 155, 186];
    const points = lengths.map((n) => point(new Uint8Array(n).fill(120)));
    expect(new Set(points).size).toBe(lengths.length);
  });

  it("bytesToFieldElements packs 31-byte LE chunks", () => {
    expect(bytesToFieldElements(new Uint8Array(11)).length).toBe(1); // "hello world" length
    expect(bytesToFieldElements(new Uint8Array(128)).length).toBe(5); // ceil(128/31)
  });
});
