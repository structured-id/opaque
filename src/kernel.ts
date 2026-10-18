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

const SLOT = "@structured-id/opaque/zkpp-kernel";
const REGISTRY = Symbol.for(SLOT);
const CONTRACT = Symbol.for("@structured-id/opaque/zkpp-kernel-contract");

/** The slot of a kernel of revision `contract` (2 and later). */
const slotOf = (contract: number) => Symbol.for(`${SLOT}@${contract}`);

/**
 * The shared slot holds a callable factory, the form every copy of this
 * package reads; a copy from before revisions calls it directly, and copies
 * of revision 1 read the revision riding on it under its own key.
 */
type RegisteredFactory = ZkppKernelFactory & { [CONTRACT]?: number };
type Registry = Record<symbol, RegisteredFactory | undefined>;

/**
 * Register the native kernel, implementing client contract `contract`. A
 * second registration replaces the first, of any revision, so reloading a
 * module during development does not strand the old factory.
 */
export function registerZkppKernel(
  factory: ZkppKernelFactory,
  contract: number,
): void {
  const registry = globalThis as Registry;
  for (const key of Object.getOwnPropertySymbols(registry))
    if (Symbol.keyFor(key)?.startsWith(`${SLOT}@`)) delete registry[key];
  // From revision 2 the finishes return objects where a copy from before
  // revisions expects the bytes it sends: that copy, calling the shared slot
  // directly, gets a refusal; this revision's copies read the kernel's own slot.
  const shared: RegisteredFactory =
    contract >= 2
      ? async () => {
          throw new Error(
            `ZKPP kernel implements client contract ${contract}; this copy of @structured-id/opaque predates kernel contract revisions`,
          );
        }
      : (kernel) => factory(kernel);
  shared[CONTRACT] = contract;
  registry[REGISTRY] = shared;
  if (contract >= 2) registry[slotOf(contract)] = (kernel) => factory(kernel);
}

/**
 * The registered native kernel: this revision's own slot, else the shared
 * one (another revision, or 0 for one stored without a revision).
 */
export function registeredZkppKernel(): ZkppKernelRegistration | undefined {
  const registry = globalThis as Registry;
  const own = registry[slotOf(ZKPP_KERNEL_CONTRACT)];
  if (own !== undefined)
    return { factory: own, contract: ZKPP_KERNEL_CONTRACT };
  const entry = registry[REGISTRY];
  if (entry === undefined) return undefined;
  return { factory: entry, contract: entry[CONTRACT] ?? 0 };
}
