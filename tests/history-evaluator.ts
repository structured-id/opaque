// The server side of a password operation's history evaluation, for browser
// tests without a server: an operation with fresh evaluator keys, and the
// evaluated element of the client's blinded input under each key with its
// DLEQ proof, as the evaluator service answers them. The client verifies every
// proof against the domain's key for the operation before it proves, so a
// challenge computed differently from the server's fails these tests rather
// than passing silently.
import { expand_message_xmd } from "@noble/curves/abstract/hash-to-curve.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Pallas, type Point } from "../src/curve.js";
import { Fp, Fq } from "../src/field.js";
import type {
  PasswordHistoryContext,
  PasswordHistoryEvaluation,
  ZkppClient,
  ZkppProgress,
} from "../src/index.js";

/** Domain separator of the evaluation proof challenge. */
const DLEQ_DST = new TextEncoder().encode("SID-HISTORY-VOPRF-DLEQ-v1");

const random = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));

/** A uniformly random Pallas scalar. */
const randomScalar = (): bigint => Fq.fromUniformBytes(random(64));

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/**
 * The Chaum-Pedersen challenge over `points` = [pk, B, Z, T2, T3], bound to
 * the operation: hash-to-scalar (RFC 9380 expand_message_xmd, SHA-256, 64
 * bytes reduced into the scalar field) of the length-prefixed context and the
 * compressed points, under the evaluator's domain separator.
 */
function challenge(context: Uint8Array, points: Point[]): bigint {
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, context.length, true);
  const msg = concat([len, context, ...points.map(Pallas.toBytes)]);
  return Fq.fromUniformBytes(expand_message_xmd(msg, DLEQ_DST, 64, sha256));
}

export interface TestEvaluator {
  /** The operation as its preparing step would hand it to the client. */
  context: PasswordHistoryContext;
  /** Answer `blinded` under every domain's key, each proof bound to the operation. */
  evaluate(blinded: Uint8Array): PasswordHistoryEvaluation[];
}

/** An operation over `domains` comparison domains with fresh evaluator keys. */
export function testEvaluator(domains = 1): TestEvaluator {
  const keys = Array.from({ length: domains }, randomScalar);
  const operationId = random(16);
  const G = Pallas.GENERATOR;
  const context: PasswordHistoryContext = {
    operationId,
    ownerDomain: Fp.toBytes(Fp.fromUniformBytes(random(64))),
    domains: keys.map((k, j) => ({
      comparisonDomain: Fp.toBytes(BigInt(1000 + j)),
      evaluatorPublicKey: Pallas.toBytes(Pallas.scalarMul(k, G)),
    })),
    policyVersion: 1,
  };
  return {
    context,
    evaluate(blinded) {
      const b = Pallas.fromBytes(blinded);
      return keys.map((k) => {
        const z = Pallas.scalarMul(k, b);
        const nonce = randomScalar();
        const c = challenge(operationId, [
          Pallas.scalarMul(k, G),
          b,
          z,
          Pallas.scalarMul(nonce, G),
          Pallas.scalarMul(nonce, b),
        ]);
        return {
          evaluatedElement: Pallas.toBytes(z),
          proof: {
            challenge: Fq.toBytes(c),
            response: Fq.toBytes(Fq.sub(nonce, Fq.mul(c, k))),
          },
        };
      });
    },
  };
}

/**
 * One password operation as the client runs it against `evaluator`: the OPAQUE
 * start, the history request and its evaluation, then the proof.
 */
export async function installPassword(
  client: ZkppClient,
  password: string,
  evaluator: TestEvaluator,
  onProgress?: (p: ZkppProgress) => void,
) {
  const start = await client.registrationStart(password);
  const request = await client.historyRequest(
    password,
    evaluator.context.ownerDomain,
  );
  const proof = await client.prove(password, start, {
    context: evaluator.context,
    history: request && {
      request,
      evaluations: evaluator.evaluate(request.blinded),
    },
    onProgress,
  });
  return { start, request, proof };
}
