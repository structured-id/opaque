/**
 * Gadget A (policy engine) witness — byte-identical to sid-pake-core gadget_a.
 * Per password byte over MAX_PASSWORD_LEN rows: byte, active=(i<len), the four
 * char-class flags (classify when active), and running class accumulators.
 * Compliance = final accumulators meet the policy minimums.
 */
export const MAX_PASSWORD_LEN = 128;

export interface PolicyParams {
  minLength: number;
  minUpper: number;
  minLower: number;
  minDigit: number;
  minSymbol: number;
}

/** ASCII char-class membership (upper, lower, digit, symbol). */
export function classify(b: number): [boolean, boolean, boolean, boolean] {
  return [
    b >= 65 && b <= 90,
    b >= 97 && b <= 122,
    b >= 48 && b <= 57,
    (b >= 33 && b <= 47) || (b >= 58 && b <= 64) || (b >= 91 && b <= 96) || (b >= 123 && b <= 126),
  ];
}

export interface GadgetAWitness {
  byte: number[];
  active: number[];
  isU: number[];
  isL: number[];
  isD: number[];
  isS: number[];
  accU: number[];
  accL: number[];
  accD: number[];
  accS: number[];
  final: [number, number, number, number];
  compliant: boolean;
}

export function gadgetAWitness(pw: number[], policy: PolicyParams, n = MAX_PASSWORD_LEN): GadgetAWitness {
  const len = pw.length;
  const w: GadgetAWitness = {
    byte: [], active: [], isU: [], isL: [], isD: [], isS: [],
    accU: [], accL: [], accD: [], accS: [], final: [0, 0, 0, 0], compliant: false,
  };
  let [au, al, ad, as_] = [0, 0, 0, 0];
  for (let i = 0; i < n; i++) {
    const active = i < len;
    const b = active ? pw[i] : 0;
    const [u, l, d, s] = active ? classify(b) : [false, false, false, false];
    au += u ? 1 : 0;
    al += l ? 1 : 0;
    ad += d ? 1 : 0;
    as_ += s ? 1 : 0;
    w.byte.push(b);
    w.active.push(active ? 1 : 0);
    w.isU.push(u ? 1 : 0);
    w.isL.push(l ? 1 : 0);
    w.isD.push(d ? 1 : 0);
    w.isS.push(s ? 1 : 0);
    w.accU.push(au);
    w.accL.push(al);
    w.accD.push(ad);
    w.accS.push(as_);
  }
  w.final = [au, al, ad, as_];
  w.compliant =
    len >= policy.minLength &&
    au >= policy.minUpper &&
    al >= policy.minLower &&
    ad >= policy.minDigit &&
    as_ >= policy.minSymbol;
  return w;
}
