/**
 * ZKPP client loader. Picks the fastest kernel the platform runs: a registered
 * native WebAssembly kernel (kernel.ts) on a cross-origin-isolated page with
 * threads, else this package's TypeScript client (backend-ts.ts).
 *
 * A password is installed (a first password, a change or an authorized reset)
 * in one server-side operation. The server's preparing step (registration
 * start, password-change challenge, password-reset verification) returns the
 * operation's {@link PasswordHistoryContext}; the client blinds its history
 * input ({@link ZkppClient.historyRequest}), has the server's history
 * evaluator answer it, and proves policy and history over the same password
 * ({@link ZkppClient.prove}). The proof is bound to the operation and to the
 * OPAQUE registration request of {@link ZkppClient.registrationStart}: both
 * enter its transcript, and the request shares its OPRF blind with the proof,
 * so the proof verifies for no other operation, request or password. Both
 * clients derive their key from the circuit itself on first use
 * ({@link ZkppClient.prepare}); no key material comes from the server.
 */
import {
  detectCapabilities,
  isWasmKernel,
  selectKernel,
  selectTsKernel,
  type Capabilities,
  type Kernel,
  type TsKernel,
  type WasmKernel,
} from "./capabilities.js";
import { registeredZkppKernel } from "./kernel.js";
import type { ZkppProgress } from "./progress.js";
import { createTsClient } from "./backend-ts.js";
import type { ProverHostOptions } from "./zkpp/prover-host.js";

/** One comparison domain of an operation (proto `PasswordHistoryDomain`). */
export interface PasswordHistoryDomain {
  /** The domain element: 32 bytes, a Pallas base-field element, little-endian. */
  comparisonDomain: Uint8Array;
  /** The evaluator's public key for this domain: a compressed Pallas point, 32 bytes. */
  evaluatorPublicKey: Uint8Array;
}

/**
 * What the server's preparing step hands the client for one operation (proto
 * `PasswordHistoryContext`).
 */
export interface PasswordHistoryContext {
  /** The operation, 16 bytes; every later step of it carries this id. */
  operationId: Uint8Array;
  /** The owner's history input domain: 32 bytes, a Pallas base-field element. */
  ownerDomain: Uint8Array;
  /** The comparison domains, in the order the evaluations and the proof's tags follow. */
  domains: PasswordHistoryDomain[];
  /** The policy version the proof is made for. */
  policyVersion: number;
}

/** The client's blinded history input for one password. */
export interface PasswordHistoryRequest {
  /** The blind; stays with the client until it proves. */
  blind: Uint8Array;
  /**
   * The blinded input B (proto `EvaluatePasswordHistoryRequest.blinded_input`):
   * what the evaluator gets, a compressed Pallas point of 32 bytes.
   */
  blinded: Uint8Array;
}

/** The evaluator's answer for one domain (proto `PasswordHistoryEvaluation`). */
export interface PasswordHistoryEvaluation {
  /** Z = k·B under the domain's key: a compressed Pallas point, 32 bytes. */
  evaluatedElement: Uint8Array;
  /**
   * DLEQ proof that Z uses the key behind the domain's `evaluatorPublicKey`:
   * two Pallas scalars, 32 bytes each.
   */
  proof: { challenge: Uint8Array; response: Uint8Array };
}

/** The history request the client made and the evaluator's answers to it. */
export interface PasswordHistoryInputs {
  request: PasswordHistoryRequest;
  /** One per `PasswordHistoryContext.domains` entry, in that order. */
  evaluations: PasswordHistoryEvaluation[];
}

/**
 * A registration proof bound to one operation and request (proto
 * `PasswordRegistrationProof`).
 */
export interface ZkppProof {
  /** Halo2 proof bytes (proto `zkpp_proof`). */
  proof: Uint8Array;
  /** The proof's public instances, 32 bytes each (proto `instances`). */
  instances: Uint8Array[];
}

export interface ZkppRegistrationStart {
  /** OPAQUE RegistrationRequest on Pallas (proto `registration_request`). */
  request: Uint8Array;
  /**
   * Client state for {@link ZkppClient.prove} and
   * {@link ZkppClient.registrationFinish}; keep it local.
   */
  state: string;
}

export interface ZkppLoginStart {
  /** OPAQUE CredentialRequest on Pallas (KE1). */
  request: Uint8Array;
  /** Client state for {@link ZkppClient.loginFinish}; keep it local. */
  state: string;
}

export interface ProveOptions {
  /** The operation's history context, from the server's preparing step. */
  context: PasswordHistoryContext;
  /**
   * The history request and the evaluator's answers to it; `null` only when
   * {@link ZkppClient.historyRequest} gave none.
   */
  history: PasswordHistoryInputs | null;
  /** Progress callback for a UI gauge: fires with monotonic `fraction` 0..1. */
  onProgress?: (p: ZkppProgress) => void;
}

export interface ZkppClient {
  readonly kernel: Kernel;
  /**
   * True once the client can answer no more calls (a worker it runs on
   * stopped); every call then fails at once. The operation in progress
   * fails; load a new client for the next operation.
   */
  readonly stopped: boolean;
  /**
   * Derive the key for `policyVersion` over `historyDomains` comparison
   * domains now (the client builds it itself, from the circuit alone), so a
   * later {@link prove} does not wait for it. Calling it again for the same
   * shape costs nothing; `prove` prepares on its own when this was skipped.
   */
  prepare(
    policyVersion: number,
    historyDomains: number,
    onProgress?: (stage: string, fraction: number) => void,
  ): Promise<void>;
  /**
   * Start installing `password`: the OPAQUE request the operation's OPAQUE
   * step sends, and the client state the proof and the finish read.
   */
  registrationStart(password: string): Promise<ZkppRegistrationStart>;
  /**
   * The blinded history input of `password` under the operation's owner
   * domain, for the server's history evaluator; `null` for a password the
   * circuit cannot hold, which installs without a proof.
   */
  historyRequest(
    password: string,
    ownerDomain: Uint8Array,
  ): Promise<PasswordHistoryRequest | null>;
  /**
   * Prove `password` for the operation over the request of `start`: the
   * character policy and the history tags, bound to the operation and the
   * request. Sent with the final record. `null` for a password the circuit
   * cannot hold.
   *
   * The proof is about the password as it enters the OPRF (the request's
   * element) and nothing beyond it: the server never sees what a client
   * feeds to OPRF Finalize or its key stretching, so the final record is not
   * bound by the proof. Breach screening is not proven by this package's key:
   * its breach filter is empty.
   */
  prove(
    password: string,
    start: ZkppRegistrationStart,
    opts: ProveOptions,
  ): Promise<ZkppProof | null>;
  /**
   * Finish against the server's RegistrationResponse: the OPAQUE
   * RegistrationRecord (proto `registration_record`).
   */
  registrationFinish(
    password: string,
    state: string,
    response: Uint8Array,
  ): Promise<Uint8Array>;
  /** Start signing in with a Pallas OPAQUE credential. */
  loginStart(password: string): Promise<ZkppLoginStart>;
  /** Finish signing in; returns KE3. A wrong password fails here. */
  loginFinish(
    password: string,
    state: string,
    response: Uint8Array,
  ): Promise<Uint8Array>;
}

/** A WASM kernel was asked for and none is registered. */
export class ZkppUnavailableError extends Error {
  constructor(readonly kernel: Kernel) {
    super(`ZKPP kernel "${kernel}" needs a registered native kernel`);
    this.name = "ZkppUnavailableError";
  }
}

/** The selected native kernel did not load; the loader picked `to` instead. */
export interface ZkppKernelFallback {
  from: WasmKernel;
  to: TsKernel;
  /** Why the native kernel did not load. */
  reason: unknown;
}

export interface LoadZkppOptions {
  /**
   * The kernel to load. Absent: the fastest the platform runs, with the
   * fallback below. An explicitly requested kernel is never replaced.
   */
  kernel?: Kernel;
  /** The TypeScript client's workers. */
  prover?: ProverHostOptions;
  /** The platform's capabilities; detected when absent. */
  capabilities?: Capabilities;
  /** Told when the selected native kernel did not load; the log otherwise. */
  onFallback?: (fallback: ZkppKernelFallback) => void;
}

/**
 * The client for `options.kernel`, or for the fastest kernel the platform
 * runs: the registered native kernel for a WASM tier, this package's
 * TypeScript client otherwise. A selected native kernel that does not load
 * (its artifacts unreachable, a compile failure) is unavailable: the loader
 * picks the TypeScript tier while loading, before the client holds any
 * operation's cryptographic state, and reports why. Once a client is loaded,
 * its failure is the operation's failure; no operation is retried on another
 * kernel.
 */
export async function loadZkppClient(
  options: LoadZkppOptions = {},
): Promise<ZkppClient> {
  const { prover = {} } = options;
  if (options.kernel !== undefined) return load(options.kernel, prover);
  const capabilities = options.capabilities ?? detectCapabilities();
  const kernel = selectKernel(capabilities);
  if (!isWasmKernel(kernel)) return load(kernel, prover);
  try {
    return await load(kernel, prover);
  } catch (reason) {
    const to = selectTsKernel(capabilities);
    const fallback = { from: kernel, to, reason };
    if (options.onFallback) options.onFallback(fallback);
    else
      console.warn(`ZKPP kernel ${kernel} did not load; using ${to}:`, reason);
    return load(to, prover);
  }
}

/** The client for exactly `kernel`. */
async function load(
  kernel: Kernel,
  prover: ProverHostOptions,
): Promise<ZkppClient> {
  if (!isWasmKernel(kernel)) return createTsClient(kernel, prover);
  const native = registeredZkppKernel();
  if (!native) throw new ZkppUnavailableError(kernel);
  return native(kernel);
}
