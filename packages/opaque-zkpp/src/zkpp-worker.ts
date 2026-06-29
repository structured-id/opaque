/**
 * Web Worker entry for the pure-TS prover's per-column work (commit + FFT). The
 * worker-pool spawns N of these; each handles one advice column per message. If
 * Web Workers are unavailable, worker-pool.ts runs `processColumn` inline instead.
 */
/// <reference lib="webworker" />
import { processColumn, type ColumnTask } from './zkpp-worker-kernel.js';

declare const self: DedicatedWorkerGlobalScope;

self.onmessage = (e: MessageEvent<ColumnTask>) => {
  self.postMessage(processColumn(e.data));
};
