/**
 * Registry of native ZKPP kernels. The package itself ships only the
 * TypeScript kernels; a separately distributed WebAssembly kernel registers
 * itself here when it is imported (`import "<kernel package>/register"`), and
 * the loader prefers it wherever the platform can run it.
 *
 * Registration goes through a registry on `globalThis`, keyed by a
 * `Symbol.for` name, so a kernel registered against one copy of this package
 * is seen by every other copy a bundler may have duplicated. Those copies and
 * the kernel are released separately, so a registration names the revision of
 * the {@link ZkppClient} contract the kernel implements, and the loader takes
 * only a kernel of its own revision.
 */
import type { WasmKernel } from "./capabilities.js";
import type { ZkppClient } from "./loader.js";

/** A native kernel: builds a client that runs on the given WASM tier. */
export type ZkppKernelFactory = (kernel: WasmKernel) => Promise<ZkppClient>;

/**
 * The revision of the {@link ZkppClient} contract this package calls. 1:
 * `loginFinish` takes the OPAQUE context (RFC 9807 §6). A kernel states the
 * revision it implements as its own constant, not by importing this one.
 */
export const ZKPP_KERNEL_CONTRACT = 1;

/** A registered native kernel and the contract revision it implements. */
export interface ZkppKernelRegistration {
  factory: ZkppKernelFactory;
  contract: number;
}

/** The registered kernel implements another revision of the client contract. */
export class ZkppKernelContractError extends Error {
  constructor(
    readonly kernel: WasmKernel,
    /** The kernel's revision; 0 when it registered without one. */
    readonly contract: number,
  ) {
    super(
      `ZKPP kernel "${kernel}" implements client contract ${contract}, this package needs ${ZKPP_KERNEL_CONTRACT}`,
    );
    this.name = "ZkppKernelContractError";
  }
}

const REGISTRY = Symbol.for("@structured-id/opaque/zkpp-kernel");
const CONTRACT = Symbol.for("@structured-id/opaque/zkpp-kernel-contract");

/**
 * The slot holds a callable factory, the form every copy of this package
 * reads, including one from before the revision, which calls it directly;
 * the revision rides on it under its own key.
 */
type RegisteredFactory = ZkppKernelFactory & { [CONTRACT]?: number };
type Registry = { [REGISTRY]?: RegisteredFactory };

/**
 * Register the native kernel, implementing client contract `contract`. A
 * second registration replaces the first, so reloading a module during
 * development does not strand the old factory.
 */
export function registerZkppKernel(
  factory: ZkppKernelFactory,
  contract: number,
): void {
  // A wrapper carries the revision, so the kernel's own function is not mutated.
  const entry: RegisteredFactory = (kernel) => factory(kernel);
  entry[CONTRACT] = contract;
  (globalThis as Registry)[REGISTRY] = entry;
}

/** The registered native kernel, if any; one stored without a revision is revision 0. */
export function registeredZkppKernel(): ZkppKernelRegistration | undefined {
  const entry = (globalThis as Registry)[REGISTRY];
  if (entry === undefined) return undefined;
  return { factory: entry, contract: entry[CONTRACT] ?? 0 };
}
