/* tslint:disable */
/* eslint-disable */

/**
 * Generate ZKPP proof for password registration or change.
 *
 * Returns JSON: `{"proof": "base64", "instances": ["b64", ...]}`
 */
export function generate_zkpp_proof(password: string, policy_version: number, mode: string, prev_commitment?: string | null): string;

/**
 * Get password policy parameters by version.
 *
 * Returns JSON: `{"version": N, "minLength": N, ...}`
 */
export function get_policy(version: number): string;

export function init_panic_hook(): void;

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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly prepare_breach_check: (a: number, b: number) => [number, number];
    readonly verify_breach_response: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly generate_zkpp_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly get_policy: (a: number) => [number, number, number, number];
    readonly validate_password: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly init_panic_hook: () => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
