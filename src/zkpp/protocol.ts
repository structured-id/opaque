/** Messages between the page's prover host and the prover worker. */
import type { ProveJob, ProveResult } from "./prover-core.js";

export type HostMessage =
  /** The lanes' ports, once, before anything else. */
  | { t: "init"; ports: MessagePort[] }
  | { t: "prepare"; id: number; policyVersion: number; historyDomains: number }
  | { t: "prove"; id: number; job: ProveJob }
  /** How many lanes may compute at once (the tab's visibility changed). */
  | { t: "active"; lanes: number };

export type WorkerMessage =
  | { t: "progress"; id: number; stage: string; fraction: number }
  | { t: "done"; id: number; result: ProveResult | null }
  | { t: "error"; id: number; message: string };
