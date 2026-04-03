// Type declarations for wasm-bindgen generated module (dist/sid_wasm.js).
// The actual module is copied to dist/ during build.
// This declaration allows typecheck to pass before build.

declare module '../../dist/sid_wasm.js' {
  export function validate_password(password: string, policy_json: string): string;
  export function get_policy(version: number): string;
  export function prepare_breach_check(password: string): string;
  export function verify_breach_response(password: string, hibp_response: string): string;
  export function generate_zkpp_proof(
    password: string,
    policy_version: number,
    mode: string,
    prev_commitment?: string | null,
  ): string;
  export default function init(): Promise<void>;
}
