/**
 * Registry of native ZKPP kernels. The package itself ships only the
 * TypeScript kernels; a separately distributed WebAssembly kernel registers
 * itself here when it is imported (`import "<kernel package>/register"`), and
 * the loader prefers it wherever the platform can run it.
 *
 * Registration goes through a registry on `globalThis`, keyed by a
 * `Symbol.for` name, so a kernel registered against one copy of this package
 * is seen by every other copy a bundler may have duplicated.
 */
import type { WasmKernel } from "./capabilities.js";
import type { ZkppClient } from "./loader.js";

/** A native kernel: builds a client that runs on the given WASM tier. */
export type ZkppKernelFactory = (kernel: WasmKernel) => Promise<ZkppClient>;

const REGISTRY = Symbol.for("@structured-id/opaque/zkpp-kernel");

type Registry = { [REGISTRY]?: ZkppKernelFactory };

/**
 * Register the native kernel. A second registration replaces the first, so
 * reloading a module during development does not strand the old factory.
 */
export function registerZkppKernel(factory: ZkppKernelFactory): void {
  (globalThis as Registry)[REGISTRY] = factory;
}

/** The registered native kernel, if any. */
export function registeredZkppKernel(): ZkppKernelFactory | undefined {
  return (globalThis as Registry)[REGISTRY];
}
