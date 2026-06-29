/**
 * Web Worker entry for the coset FFT stage: receives one column (Lagrange basis)
 * and returns its extended-domain coset (coeff -> extended), the exact `toCos` the
 * prover runs inline. Pure (no SRS), so the result is byte-identical to the inline
 * path; only the messaging differs. Used by create-proof.ts via the worker pool in
 * browsers; in Node the pool falls back to inline and this file is never loaded.
 */
import { coeffToExtended, lagrangeToCoeff } from "./domain.js";

const K = 11;
const EXTK = 14;

// Avoid DOM/WebWorker lib dependency: type the worker globals structurally.
const ctx = globalThis as unknown as {
  onmessage: ((e: { data: bigint[] }) => void) | null;
  postMessage: (m: bigint[]) => void;
};

ctx.onmessage = (e) => {
  ctx.postMessage(coeffToExtended(lagrangeToCoeff(e.data, K), EXTK));
};
