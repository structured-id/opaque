// OPAQUE on Pallas, TypeScript client against the Rust reference: each vector
// is a registration and a login of the reference client (opaque-ke 4.0.1 over
// PallasCipherSuite) against the reference server, with the client's RNG
// output recorded in draw order (fixtures/opaque-vectors.json, from the
// sid-pake-core `opaque_vectors` example). Replaying that byte stream, the TS
// client must emit the same request, state, record and KE3, derive the same
// session and export keys, and fail a wrong password at the same step.
import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import {
  loginFinish,
  loginStart,
  registrationFinish,
  registrationStart,
} from "../src/opaque/client.js";
import { fromBase64 } from "../src/opaque/bytes.js";
import { createTsClient } from "../src/backend-ts.js";
import type { RandomSource } from "../src/random.js";

interface Vector {
  password: string;
  loginPassword: string;
  /** The sign-in's OPAQUE context, hex; empty for an ordinary sign-in. */
  context: string;
  registrationStartDrawn: string;
  registrationRequest: string;
  registrationState: string;
  registrationResponse: string;
  registrationFinishDrawn: string;
  registrationRecord: string;
  loginStartDrawn: string;
  credentialRequest: string;
  loginState: string;
  credentialResponse: string;
  finalization?: string;
  sessionKey?: string;
  exportKey?: string;
  registrationExportKey?: string;
  loginError?: string;
}

const vectors: Vector[] = JSON.parse(
  readFileSync(
    new URL("./fixtures/opaque-vectors.json", import.meta.url),
    "utf8",
  ),
);

const unhex = (h: string): Uint8Array =>
  Uint8Array.from(h.match(/.{2}/g) ?? [], (b) => parseInt(b, 16));
const hex = (b: Uint8Array): string =>
  [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
const stateHex = (state: string): string => hex(fromBase64(state, "state"));

/** Replays `drawn` in order and fails if the client draws more or less. */
function replay(drawn: string): RandomSource & { done(): void } {
  const bytes = unhex(drawn);
  let at = 0;
  const rng = ((n: number) => {
    if (at + n > bytes.length) throw new Error("drew past the recorded stream");
    const out = bytes.slice(at, at + n);
    at += n;
    return out;
  }) as RandomSource & { done(): void };
  rng.done = () => expect(at).toBe(bytes.length);
  return rng;
}

describe("OPAQUE on Pallas matches the Rust reference", () => {
  vectors.forEach((v, i) => {
    it(`vector ${i}: registration`, async () => {
      const password = unhex(v.password);
      const startRng = replay(v.registrationStartDrawn);
      const start = registrationStart(password, startRng);
      startRng.done();
      expect(hex(start.request)).toBe(v.registrationRequest);
      expect(stateHex(start.state)).toBe(v.registrationState);

      const finishRng = replay(v.registrationFinishDrawn);
      const record = await registrationFinish(
        password,
        start.state,
        unhex(v.registrationResponse),
        finishRng,
      );
      finishRng.done();
      expect(hex(record)).toBe(v.registrationRecord);
    }, 60000);

    it(`vector ${i}: login`, async () => {
      const password = unhex(v.loginPassword);
      const rng = replay(v.loginStartDrawn);
      const start = loginStart(password, rng);
      rng.done();
      expect(hex(start.request)).toBe(v.credentialRequest);
      expect(stateHex(start.state)).toBe(v.loginState);

      const finishing = loginFinish(
        password,
        start.state,
        unhex(v.credentialResponse),
        unhex(v.context),
      );
      if (v.loginError) {
        // A wrong password fails when the envelope does not open, with the
        // error a caller recognises as a refused password.
        await expect(finishing).rejects.toMatchObject({
          name: "ZkppInvalidLoginError",
        });
        return;
      }
      const done = await finishing;
      expect(hex(done.finalization)).toBe(v.finalization);
      expect(hex(done.sessionKey)).toBe(v.sessionKey);
      expect(hex(done.exportKey)).toBe(v.exportKey);
      expect(v.exportKey).toBe(v.registrationExportKey);
    }, 60000);
  });

  // The context's length is a two-byte field of the preamble (RFC 9807 §6):
  // a longer one cannot be encoded and is refused before any computation.
  it("refuses a context longer than 65535 bytes", async () => {
    const v = vectors[0];
    const password = unhex(v.loginPassword);
    const start = loginStart(password, replay(v.loginStartDrawn));
    await expect(
      loginFinish(
        password,
        start.state,
        unhex(v.credentialResponse),
        new Uint8Array(0x10000),
      ),
    ).rejects.toThrow("OPAQUE context too long");
  });

  // The packaged TypeScript client passes the context through to the
  // sign-in: it finishes the reference's sign-in under its context.
  it("finishes a sign-in under a context through the TypeScript client", async () => {
    const v = vectors.find((c) => c.context !== "")!;
    const state = loginStart(
      unhex(v.loginPassword),
      replay(v.loginStartDrawn),
    ).state;
    const client = createTsClient("ts");
    const finalization = await client.loginFinish(
      new TextDecoder().decode(unhex(v.loginPassword)),
      state,
      unhex(v.credentialResponse),
      unhex(v.context),
    );
    expect(hex(finalization)).toBe(v.finalization);
  });

  // An ordinary sign-in may leave the context out: it is the empty one, the
  // RFC 9807 default, so a caller written before the argument existed still
  // signs in.
  it("finishes an ordinary sign-in without a context argument", async () => {
    const v = vectors.find(
      (c: { context: string; finalization?: string }) =>
        c.context === "" && c.finalization,
    );
    const password = unhex(v.loginPassword);
    const start = loginStart(password, replay(v.loginStartDrawn));
    const finished = await loginFinish(
      password,
      start.state,
      unhex(v.credentialResponse),
    );
    expect(hex(finished.finalization)).toBe(v.finalization);
  });

  // A sign-in inside another operation verifies only under that operation's
  // context: the reference server's answer made under it does not finish as
  // an ordinary sign-in, so neither can stand for the other.
  it("finishes a sign-in only under the context it was made for", async () => {
    const v = vectors.find((c: { context: string }) => c.context !== "");
    expect(v).toBeDefined();
    const password = unhex(v.loginPassword);
    const start = loginStart(password, replay(v.loginStartDrawn));
    await expect(
      loginFinish(
        password,
        start.state,
        unhex(v.credentialResponse),
        new Uint8Array(0),
      ),
    ).rejects.toMatchObject({ name: "ZkppInvalidLoginError" });
  });

  // Only a sign-in that does not verify is a refused password: a malformed
  // response fails with its own error, so a caller does not ask the user to
  // retype a password that was never judged.
  it("fails a malformed response with its own error, not a refused password", async () => {
    const v = vectors[0];
    const password = unhex(v.loginPassword);
    const start = loginStart(password, replay(v.loginStartDrawn));
    const failure = await loginFinish(
      password,
      start.state,
      unhex(v.credentialResponse).slice(1),
    ).catch((e: unknown) => e);
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).name).not.toBe("ZkppInvalidLoginError");
  });

  it("refuses a registration response that reflects the request", async () => {
    const v = vectors[0];
    const password = unhex(v.password);
    const start = registrationStart(password, replay(v.registrationStartDrawn));
    const reflected = unhex(v.registrationResponse);
    reflected.set(start.request, 0);
    await expect(
      registrationFinish(password, start.state, reflected),
    ).rejects.toThrow("reflects the request");
  });

  it("refuses an identity server key", async () => {
    const v = vectors[0];
    const password = unhex(v.password);
    const start = registrationStart(password, replay(v.registrationStartDrawn));
    const response = unhex(v.registrationResponse);
    response.fill(0, 32);
    await expect(
      registrationFinish(password, start.state, response),
    ).rejects.toThrow("identity");
  });

  it("refuses a response of the wrong length", async () => {
    const v = vectors[0];
    const password = unhex(v.password);
    const start = registrationStart(password, replay(v.registrationStartDrawn));
    await expect(
      registrationFinish(
        password,
        start.state,
        unhex(v.registrationResponse).subarray(0, 63),
      ),
    ).rejects.toThrow("too short");
  });

  it("refuses an empty password", () => {
    expect(() => registrationStart(new Uint8Array(0))).toThrow("empty");
    expect(() => loginStart(new Uint8Array(0))).toThrow("empty");
  });
});
