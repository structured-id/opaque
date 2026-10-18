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
 * `loginFinish` takes the OPAQUE context (RFC 9807 §6). 2: `registrationFinish`
 * and `loginFinish` also return the credential's export key. A kernel states
 * the revision it implements as its own constant, not by importing this one.
 */
export const ZKPP_KERNEL_CONTRACT = 2;

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
const KERNEL = Symbol.for("@structured-id/opaque/zkpp-kernel-factory");

/**
 * The one slot holds a callable factory, the form every copy of this package
 * reads: a copy from before revisions calls it directly, and copies of
 * revision 1 read the revision riding on it under its own key. From revision
 * 2 the kernel's factory rides on it too, so any later registration, by a
 * copy of any revision, replaces the whole entry.
 */
type RegisteredFactory = ZkppKernelFactory & {
  [CONTRACT]?: number;
  [KERNEL]?: ZkppKernelFactory;
};
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
  // From revision 2 the finishes return objects where a copy from before
  // revisions expects the bytes it sends: that copy, calling the slot
  // directly, gets a refusal; copies of these revisions read the factory
  // riding on it.
  const entry: RegisteredFactory =
    contract >= 2
      ? async () => {
          throw new Error(
            `ZKPP kernel implements client contract ${contract}; this copy of @structured-id/opaque predates kernel contract revisions`,
          );
        }
      : (kernel) => factory(kernel);
  entry[CONTRACT] = contract;
  if (contract >= 2) entry[KERNEL] = (kernel) => factory(kernel);
  (globalThis as Registry)[REGISTRY] = entry;
}

/** The registered native kernel, if any; one stored without a revision is revision 0. */
export function registeredZkppKernel(): ZkppKernelRegistration | undefined {
  const entry = (globalThis as Registry)[REGISTRY];
  if (entry === undefined) return undefined;
  const contract = entry[CONTRACT] ?? 0;
  return { factory: entry[KERNEL] ?? entry, contract };
}
