# Copilot Instructions for @structured-id/opaque

## Project Context

A TypeScript client for OPAQUE (RFC 9807) on the Pallas curve together with a
Zero-Knowledge Password Policy (ZKPP) proof: a Halo2 proof over the Pasta
curves that the password meets the server's policy and was not used on the
account before, bound to the password operation and to the OPAQUE request.

The package ships only TypeScript. A native WebAssembly kernel is distributed
separately and registers itself through `registerZkppKernel`; the loader
prefers it where the page is cross-origin isolated and has threads, and falls
back to the TypeScript kernel otherwise. Both kernels must produce the same
bytes for the same inputs.

## Code Review Guidelines

### Security (Critical)

- Flag any use of `Math.random()`: randomness comes from `crypto.getRandomValues()`.
- Flag any operation that leaks password material (logging, error messages, stack traces).
- Secret comparisons are constant-time; no early return on mismatch.
- Transcript and hash domains are byte-exact with the Rust reference; flag any
  change to a domain string, field order or encoding that is not mirrored there.

### TypeScript Conventions

- `Uint8Array` for binary data, never `Buffer` (browser-compatible library).
- Field elements are `bigint`; curve points use the types in `src/curve.ts`.
- WebCrypto and `@noble/*` only; no Node `crypto` module imports in `src/`.

### Testing

- `vitest`, not `jest`. Node tests in `tests/*.test.ts`, real-browser tests in
  `tests/*.browser.test.ts`.
- Prover stages are checked byte-exact against fixtures dumped from the Rust
  reference (`tests/fixtures/`).

### Commit Messages (Conventional Commits)

```
<type>[(scope)]: <description>
```

Valid types: `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`,
`chore`, `style`. Title imperative, lowercase, no period, at most 50 characters.
Breaking changes: `feat!:` or a `BREAKING CHANGE:` footer.
