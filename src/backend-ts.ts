/**
 * The package's own ZKPP client: OPAQUE on Pallas, the history request and
 * the registration proof, all in TypeScript. The proof runs in workers (see
 * prover-host.ts) on `ts-threaded` and on the calling thread on `ts`; the
 * key is derived by the client on first use, never downloaded.
 */
import type { TsKernel } from "./capabilities.js";
import { Pallas } from "./curve.js";
import { Fp, Fq } from "./field.js";
import {
  blindRequest,
  historyInput,
  randomBlind,
  verifyEvaluation,
} from "./history.js";
import * as opaque from "./opaque/client.js";
import { MAX_PASSWORD_LEN } from "./opaque/oprf.js";
import { ProgressTracker, stageOf } from "./progress.js";
import { secureRandom } from "./random.js";
import type {
  PasswordHistoryRequest,
  ProveOptions,
  ZkppClient,
  ZkppProof,
  ZkppRegistrationStart,
} from "./loader.js";
import {
  createProver,
  type Prover,
  type ProverHostOptions,
} from "./zkpp/prover-host.js";

const utf8 = (s: string) => new TextEncoder().encode(s);

const point = (bytes: Uint8Array, what: string) => {
  const p = Pallas.fromBytes(bytes);
  if (p === null) throw new Error(`${what}: the identity is not accepted`);
  return p;
};

export function createTsClient(
  kernel: TsKernel,
  opts: ProverHostOptions = {},
): ZkppClient {
  let prover: Prover | null = null;
  const proverOf = (): Prover =>
    (prover ??= createProver(kernel === "ts" ? { lanes: 1 } : opts));

  return {
    kernel,

    get stopped() {
      return prover?.stopped ?? false;
    },

    async prepare(policyVersion, historyDomains, onProgress) {
      await proverOf().prepare(policyVersion, historyDomains, (stage, f) =>
        onProgress?.(stage, f),
      );
    },

    async registrationStart(password): Promise<ZkppRegistrationStart> {
      return opaque.registrationStart(utf8(password));
    },

    async historyRequest(
      password,
      ownerDomain,
    ): Promise<PasswordHistoryRequest | null> {
      const pw = utf8(password);
      if (pw.length > MAX_PASSWORD_LEN) return null;
      const r = randomBlind(secureRandom);
      const b = blindRequest(historyInput(Fp.fromBytes(ownerDomain), pw), r);
      return { blind: Fp.toBytes(r), blinded: Pallas.toBytes(b) };
    },

    async prove(password, start, o: ProveOptions): Promise<ZkppProof | null> {
      const pw = utf8(password);
      if (pw.length > MAX_PASSWORD_LEN) return null;
      if (o.history === null)
        throw new Error(
          "history: the evaluator's answers are required to prove",
        );
      const { context, history } = o;
      if (history.evaluations.length !== context.domains.length)
        throw new Error("history: one evaluation per domain");
      const d = Fp.fromBytes(context.ownerDomain);
      const r = Fp.fromBytes(history.request.blind);
      const b = blindRequest(historyInput(d, pw), r);
      const evaluations = context.domains.map((dom, j) => {
        const e = history.evaluations[j];
        const z = point(e.evaluatedElement, "evaluation");
        const ok = verifyEvaluation(
          point(dom.evaluatorPublicKey, "evaluator key"),
          b,
          z,
          context.operationId,
          {
            c: Fq.fromBytes(e.proof.challenge),
            s: Fq.fromBytes(e.proof.response),
          },
        );
        if (!ok)
          throw new Error("history: the evaluator's proof does not verify");
        return z;
      });
      const tracker = new ProgressTracker(o.onProgress);
      const result = await proverOf().prove(
        {
          password: pw,
          blind: opaque.registrationState(start.state).blind,
          operationId: context.operationId,
          request: start.request,
          policyVersion: context.policyVersion,
          d,
          domains: context.domains.map((c) => Fp.fromBytes(c.comparisonDomain)),
          r,
          evaluations,
        },
        (stage, f) => tracker.report(stageOf(stage), f),
      );
      tracker.done();
      return {
        proof: result.proof,
        instances: result.instances.map((v) => Fp.toBytes(v)),
      };
    },

    async registrationFinish(password, state, response) {
      return opaque.registrationFinish(utf8(password), state, response);
    },

    async loginStart(password) {
      return opaque.loginStart(utf8(password));
    },

    async loginFinish(password, state, response) {
      return (await opaque.loginFinish(utf8(password), state, response))
        .finalization;
    },
  };
}
