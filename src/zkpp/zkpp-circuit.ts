/** The ZKPP circuit of one key shape, as keygen and the prover take it. */
import type { ConstraintSystem } from "../halo2/constraint-system.js";
import type { Circuit } from "../halo2/keygen.js";
import type { Layouter } from "../halo2/layouter.js";
import {
  configure,
  synthesize,
  type CircuitShape,
  type ZkppWitness,
} from "./circuit.js";

export function zkppCircuit(
  shape: CircuitShape,
  witness?: ZkppWitness,
): Circuit<ReturnType<typeof configure>> {
  return {
    configure: (meta: ConstraintSystem) => configure(meta),
    synthesize: (config, layouter: Layouter) =>
      synthesize(config, layouter, shape, witness),
  };
}
