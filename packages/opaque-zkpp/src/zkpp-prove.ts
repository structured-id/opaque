/**
 * Pure-TS ZKPP registration prover (no-WASM fallback): assembles the ZkppCircuit
 * witness from a password (circuit/witness.ts) and runs the verified halo2 IPA
 * prover (create-proof.ts) to emit the 12352-byte proof, byte-exact vs Rust.
 * Imported only via the no-WASM fallback chunk (backend-ts.ts), so this heavy code
 * is code-split away from the WASM hot path.
 *
 * The fixed circuit params (SRS + proving key + constraint system) are large and
 * deployment-bundled; the caller passes them via `opts.params` (the WASM build
 * embeds them; the TS fallback loads/bundles the same blob).
 */
import { buildAdvice } from "./circuit/witness.js";
import { createProof, type ProverParams } from "./create-proof.js";
import type { PolicyParams } from "./circuit/gadget-a.js";
import type { ZkppProgress } from "./progress.js";

/** CE default password policy (>=8 chars, 1 upper, 1 lower, 1 digit). */
export const CE_DEFAULT_POLICY: PolicyParams = {
  minLength: 8,
  minUpper: 1,
  minLower: 1,
  minDigit: 1,
  minSymbol: 0,
};

export interface TsProveOptions {
  /** Run embarrassingly-parallel stages (per-column MSM/FFT, quotient) on a worker pool. */
  workers?: boolean;
  /** Fixed circuit params (SRS + pk + cs). Deployment-bundled; required to prove. */
  params?: ProverParams;
  /** Binding scalar r (from the OPAQUE flow). Defaults to the reference value. */
  r?: bigint;
  /** Password policy to prove compliance against. Defaults to the CE policy. */
  policy?: PolicyParams;
}

/**
 * Build the witness for `password` and produce the ZKPP registration proof. The
 * heavy stages report through `onProgress` for a UI gauge (0..1). Requires the
 * circuit params via `opts.params`.
 */
export async function proveRegistrationTs(
  password: string,
  _context: Uint8Array,
  onProgress?: (p: ZkppProgress) => void,
  opts: TsProveOptions = {},
): Promise<Uint8Array> {
  onProgress?.({ stage: "witness", fraction: 0, label: "Building witness" });
  if (!opts.params) {
    throw new Error(
      "pure-TS ZKPP prover: circuit params not provided — pass opts.params (deployment-bundled SRS + proving key + constraint system)",
    );
  }
  const passwordBytes = [...new TextEncoder().encode(password)];
  const { advice, instance } = buildAdvice(
    passwordBytes,
    opts.r ?? 3n,
    opts.policy ?? CE_DEFAULT_POLICY,
  );
  return createProof(advice, instance, opts.params, { onProgress });
}
