// Gate-expression evaluator: every custom gate must evaluate to 0 on all usable
// rows of the real witness (constraint satisfaction). Reads /tmp dumps — skips in CI.
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { evalAst, leHex, type Ast, type EvalCtx } from '../src/gate-eval.js';

const N = 2048;
const BF = 5;

function loadCols(path: string, tag: string, ncols: number): bigint[][] {
  const cols = Array.from({ length: ncols }, () => Array(N).fill(0n));
  for (const l of readFileSync(path, 'utf8').split('\n')) {
    const m = l.match(new RegExp(`^${tag}:(\\d+):(\\d+):(.+)$`));
    if (m) cols[+m[1]][+m[2]] = leHex(m[3]);
  }
  return cols;
}

describe('gate-expression evaluator — constraint satisfaction', () => {
  it('all 50 custom gates evaluate to 0 on every usable row of the real witness', () => {
    if (!existsSync('/tmp/sid_zkpp_advice.txt') || !existsSync('/tmp/sid_zkpp_cs.txt')) {
      console.log('SKIP: no dumps');
      return;
    }
    const advice = loadCols('/tmp/sid_zkpp_advice.txt', 'A', 53);
    const fixed = loadCols('/tmp/sid_zkpp_pk.txt', 'F', 55);
    // Instance: 1 column, values at rows 0..len-1.
    const instance = [Array(N).fill(0n)];
    for (const l of readFileSync('/tmp/sid_zkpp_instance.txt', 'utf8').split('\n')) {
      const m = l.match(/^I:(\d+):(.+)$/);
      if (m) instance[0][+m[1]] = leHex(m[2]);
    }
    const ctx: EvalCtx = { advice, fixed, instance, n: N };
    const gates: Ast[] = [];
    for (const l of readFileSync('/tmp/sid_zkpp_cs.txt', 'utf8').split('\n')) {
      const m = l.match(/^GATE:\d+:\d+:(.+)$/);
      if (m) gates.push(JSON.parse(m[1]) as Ast);
    }
    expect(gates.length).toBeGreaterThan(100);
    let nonzero = 0;
    for (const g of gates) {
      for (let r = 0; r < N - (BF + 1); r++) {
        if (evalAst(g, r, ctx) !== 0n) {
          nonzero++;
          if (nonzero <= 3) console.log(`gate nonzero at row ${r}`);
        }
      }
    }
    console.log(`GATE-EVAL: ${gates.length} polys × ${N - (BF + 1)} rows, nonzero violations=${nonzero}`);
    expect(nonzero).toBe(0);
  }, 120000);
});
