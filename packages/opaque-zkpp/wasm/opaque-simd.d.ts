/* tslint:disable */
/* eslint-disable */

/**
 * Generate ZKPP proof for password registration or change.
 *
 * Returns JSON: `{"proof": "base64", "instances": ["b64", ...]}`. `on_progress`,
 * if given, is called `(phasesDone, phasesTotal)` per prover phase for a UI bar.
 */
export function generate_zkpp_proof(password: string, policy_version: number, mode: string, prev_commitment?: string | null, on_progress?: Function | null): string;

/**
 * Generate a commit-and-prove bound registration proof. Returns JSON:
 * `{proof, instances, m, binding:{r_commit, z1, z2}}` (all base64).
 */
export function generate_zkpp_proof_bound(password: string, policy_version: number, blind: string, context: string): string;

/**
 * Get password policy parameters by version.
 *
 * Returns JSON: `{"version": N, "minLength": N, ...}`
 */
export function get_policy(version: number): string;

export function initThreadPool(num_threads: number): Promise<any>;

export function init_panic_hook(): void;

/**
 * Ship-pk: load a serialized SRS (`params`) + proving key (`pk`) so the prover
 * never runs keygen (the ~seconds cost) — they are generated once server-side and
 * fetched + cached client-side. Caches a ready `ZkppProver` for `policy_version`.
 */
export function init_zkpp_keys(params: Uint8Array, pk: Uint8Array, policy_version: number): void;

/**
 * Compute SHA-1 prefix for k-anonymity HIBP API query.
 *
 * Returns the first 5 hex characters of SHA-1(password).
 * JavaScript uses this prefix to query `https://api.pwnedpasswords.com/range/{prefix}`.
 * The full hash never leaves WASM.
 */
export function prepare_breach_check(password: string): string;

/**
 * Validate password against policy constraints.
 *
 * Returns JSON: `{"valid": true/false, "errors": ["error1", ...]}`
 */
export function validate_password(password: string, policy_json: string): string;

/**
 * Verify HIBP API response against the full password hash.
 *
 * `hibp_response` is the raw text from HIBP API (suffix:count per line).
 * Returns JSON: `{"breached": true/false, "count": N}`
 */
export function verify_breach_response(password: string, hibp_response: string): string;

export class wbg_rayon_PoolBuilder {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    build(): void;
    numThreads(): number;
    receiver(): number;
}

export function wbg_rayon_start_worker(receiver: number): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly prepare_breach_check: (a: number, b: number) => [number, number];
    readonly verify_breach_response: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly generate_zkpp_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly generate_zkpp_proof_bound: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly get_policy: (a: number) => [number, number, number, number];
    readonly init_zkpp_keys: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly validate_password: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly init_panic_hook: () => void;
    readonly __wbg_wbg_rayon_poolbuilder_free: (a: number, b: number) => void;
    readonly initThreadPool: (a: number) => any;
    readonly wbg_rayon_poolbuilder_build: (a: number) => void;
    readonly wbg_rayon_poolbuilder_numThreads: (a: number) => number;
    readonly wbg_rayon_poolbuilder_receiver: (a: number) => number;
    readonly wbg_rayon_start_worker: (a: number) => void;
    readonly memory: WebAssembly.Memory;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_thread_destroy: (a?: number, b?: number, c?: number) => void;
    readonly __wbindgen_start: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput, memory?: WebAssembly.Memory, thread_stack_size?: number }} module - Passing `SyncInitInput` directly is deprecated.
 * @param {WebAssembly.Memory} memory - Deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput, memory?: WebAssembly.Memory, thread_stack_size?: number } | SyncInitInput, memory?: WebAssembly.Memory): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory, thread_stack_size?: number }} module_or_path - Passing `InitInput` directly is deprecated.
 * @param {WebAssembly.Memory} memory - Deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory, thread_stack_size?: number } | InitInput | Promise<InitInput>, memory?: WebAssembly.Memory): Promise<InitOutput>;
