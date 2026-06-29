// Verifies the extracted buildAdvice() witness assembler reproduces the real
// circuit advice byte-exact (rows 0-2041; rows 2042+ are prover blinding, not
// witness). Reads the /tmp dump — skips in CI.
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { Fp } from "../src/field.js";
import { buildAdvice } from "../src/circuit/witness.js";
import type { PolicyParams } from "../src/circuit/gadget-a.js";

const fe = (v: bigint) =>
  [...Fp.toBytes(v)].map((x) => x.toString(16).padStart(2, "0")).join("");
const CE: PolicyParams = {
  minLength: 8,
  minUpper: 1,
  minLower: 1,
  minDigit: 1,
  minSymbol: 0,
};

describe("buildAdvice witness assembly", () => {
  it("reproduces the full circuit advice byte-exact (excluding blinding rows)", () => {
    const path = "/tmp/sid_zkpp_advice.txt";
    if (!existsSync(path)) {
      console.log("SKIP: no dump");
      return;
    }
    const { advice: cols } = buildAdvice(
      [...new TextEncoder().encode("Str0ngP@ss")],
      3n,
      CE,
    );
    let totalNz = 0,
      matched = 0,
      wrong = 0;
    for (const l of readFileSync(path, "utf8").split("\n")) {
      const m = l.match(/^A:(\d+):(\d+):(.+)$/);
      if (!m) continue;
      const c = +m[1],
        r = +m[2],
        v = m[3];
      if (BigInt("0x" + v.match(/../g)!.reverse().join("")) === 0n) continue;
      if (r >= 2042) continue; // prover blinding rows, not part of the witness
      totalNz++;
      if (fe(cols[c][r]) === v) matched++;
      else wrong++;
    }
    console.log(
      `buildAdvice: ${matched}/${totalNz} non-zero witness cells byte-exact, wrong=${wrong}`,
    );
    expect(wrong).toBe(0);
    expect(matched).toBe(totalNz);
  });
});
