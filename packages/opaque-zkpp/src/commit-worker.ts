/**
 * Web Worker entry for the commit (MSM) stage. Initialised once with the SRS
 * (Lagrange basis `gL` + blinding generator `w`), then commits one column per
 * task: `msm(poly, gL) + blind*w`. Output is a single curve point (tiny payload),
 * so unlike the coset stage this parallelizes near-linearly. Identical math to the
 * inline path. Browser-only (Node falls back to inline).
 */
import { Vesta } from "./curve.js";

type Pt = { x: bigint; y: bigint };

let gL: Pt[] | null = null;
let w: Pt | null = null;

const ctx = globalThis as unknown as {
  onmessage: ((e: { data: unknown }) => void) | null;
  postMessage: (m: unknown) => void;
};

ctx.onmessage = (e) => {
  // First message = init (SRS). Reply once to signal ready.
  if (gL === null) {
    const init = e.data as { gL: Pt[]; w: Pt };
    gL = init.gL;
    w = init.w;
    ctx.postMessage("ready");
    return;
  }
  const task = e.data as { poly: bigint[]; blind: bigint };
  const p = Vesta.add(
    Vesta.msm(task.poly, gL),
    Vesta.scalarMul(task.blind, w as Pt),
  ) as Pt;
  ctx.postMessage(p);
};
