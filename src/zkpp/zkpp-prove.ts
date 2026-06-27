/**
 * Pure-TS ZKPP registration prover — assembles the full ZkppCircuit witness and
 * runs the verified halo2 IPA prover. Imported only via the no-WASM fallback chunk
 * (backend-ts.ts), so all of this heavy code is code-split away from the hot path.
 *
 * The generic prover (advice/permutation/vanishing/multiopen/IPA) + lookup argument
 * + gadget A/B/D application witnesses are byte-exact vs halo2. The remaining port
 * is the gadget C opaque-binder witness via the halo2_gadgets ECC + Poseidon
 * in-circuit chips; until that lands this entry point reports the gap explicitly
 * rather than emitting an unsound proof.
 */
import {
  CounterRng,
  commitAdvice,
  permutationZ,
  commitPermutationZ,
  commitVanishingRandom,
  buildFoldedH,
  commitHPieces,
  buildMultiopen,
  buildIPA,
  permuteExpressionPair,
  commitLookupProduct,
  buildLookupExpressions,
} from './prover.js';
import { coeffToExtended, lagrangeToCoeff, extendedToCoeff, divideByVanishing, vanishingTInv } from './domain.js';
import { gadgetAWitness, type PolicyParams } from './circuit/gadget-a.js';
import { gadgetBDiffAcc } from './circuit/gadget-b.js';
import { breachHash, hashBits, bloomIndices } from './circuit/gadget-d.js';
import { computeHistoryCommitment } from './poseidon.js';

// Keep the machinery referenced so the bundler bundles it into this lazy chunk.
export const TS_PROVER_MACHINERY = {
  CounterRng, commitAdvice, permutationZ, commitPermutationZ, commitVanishingRandom,
  buildFoldedH, commitHPieces, buildMultiopen, buildIPA, permuteExpressionPair,
  commitLookupProduct, buildLookupExpressions, coeffToExtended, lagrangeToCoeff,
  extendedToCoeff, divideByVanishing, vanishingTInv, gadgetAWitness, gadgetBDiffAcc,
  breachHash, hashBits, bloomIndices, computeHistoryCommitment,
};

export async function proveRegistrationTs(_password: string, _context: Uint8Array): Promise<Uint8Array> {
  // The ZkppCircuit gadget C (opaque-binder) requires the halo2_gadgets ECC +
  // Poseidon in-circuit chip witness, which is still being ported byte-exact.
  throw new Error(
    'pure-TS ZKPP prover: gadget C (ECC/Poseidon in-circuit chips) witness port in progress',
  );
}
