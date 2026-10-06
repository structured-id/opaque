# @structured-id/opaque

OPAQUE (RFC 9807) on the Pallas curve together with a Zero-Knowledge Password
Policy (ZKPP) proof: the client proves that the password satisfies the
server's policy and is not one the account used before, without revealing the
password. The proof is bound to the password operation and to the OPAQUE
registration request it goes with, so it cannot be reused for another
password, operation or registration.

## Usage

A password is installed (first password, change or reset) in one server-side
operation. The server's preparing step (registration start, password-change
challenge or password-reset verification) returns the operation's history
context; the client sends its blinded history input to the history evaluator,
proves over the answers, and sends the proof with the final record.

```ts
import { loadZkppClient } from "@structured-id/opaque";

const zkpp = await loadZkppClient();

// 1. The OPAQUE request: registration start sends it with the principal;
//    a change or reset sends it in its execute step.
const start = await zkpp.registrationStart(password);

// 2. `context` is the PasswordHistoryContext the preparing step returned.
//    Blind the history input and have the evaluator answer it
//    (PasswordHistoryEvaluatorService.EvaluatePasswordHistory).
const request = await zkpp.historyRequest(password, context.ownerDomain);
const evaluations = request && (await evaluatePasswordHistory(context.operationId, request.blinded));

// 3. The proof: tens of seconds on a weak phone, so show the progress.
const proof = await zkpp.prove(password, start, {
  context,
  history: request && { request, evaluations },
  onProgress: (p) => bar.set(p.fraction),
});
// proof is null when the password cannot be proven: it then installs policy-unverified

// 4. The final record from the server's RegistrationResponse; send it with the
//    proof and the operation id in the finish step.
const record = await zkpp.registrationFinish(password, start.state, registrationResponse);
```

Sign-in uses `loginStart` / `loginFinish`. The client builds its proving key
from the circuit itself; nothing comes from the server. `prepare(policyVersion,
historyDomains)` builds it ahead of time (for example when the page opens), so
the first proof does not wait for it. The costly parts of the key are kept in
IndexedDB where the page can open it, so a later visit rebuilds the key in
under a second instead of deriving it again; the stored data is public and
checked when read.

## Kernels

`loadZkppClient` picks the fastest kernel the platform runs:

| Kernel | Where |
|--------|-------|
| `wasm-simd-threaded`, `wasm-threaded` | a registered native kernel on a cross-origin-isolated page |
| `ts-threaded` | TypeScript on a Web Worker pool (or Node `worker_threads`) |
| `ts` | TypeScript on one thread |

This package ships only TypeScript. A native WebAssembly kernel is distributed
separately; importing its registration entry point once, before the first
`loadZkppClient`, makes the WASM tiers available:

```ts
import "<native kernel package>/register";
```

The native kernel needs a cross-origin-isolated page:

```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

Without arguments `loadZkppClient` chooses the kernel while loading, before
the client holds any operation's cryptographic state. If the selected native
kernel does not load (its artifacts are unreachable or fail to compile), it is
treated as unavailable: the loader uses the TypeScript tier instead and reports
why through `onFallback`, or the console when no callback is given. Load the client when the page opens so the
download and compilation are done before the user submits a password:

```ts
const zkpp = loadZkppClient({
  onFallback: ({ from, to, reason }) => report("zkpp-kernel-fallback", { from, to, reason }),
});
```

Once a client is loaded, its failure is the operation's failure: no operation
is retried on another kernel. A kernel requested explicitly
(`loadZkppClient({ kernel })`) is never replaced; asking for a WASM tier with no
registered native kernel fails with `ZkppUnavailableError`.

## License

Apache-2.0. The ZKPP method is patent-protected; section 3 of the license
grants the patent license for this package. See `NOTICE` and `LICENSE`.
