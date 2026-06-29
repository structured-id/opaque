// @structured-id/opaque-zkpp — Zero-Knowledge Password Policy (ZKPP) prover.
//
// Patent-protected method (see NOTICE). Distributed under AGPL-3.0-only; a
// separate commercial license is available (contact structured.id).
export { loadZkppProver } from './loader.js';
export type { ZkppProver, ProveOptions } from './loader.js';
export { selectKernel } from './capabilities.js';
