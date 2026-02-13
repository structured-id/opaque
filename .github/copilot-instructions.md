# Copilot Instructions for @structured-id/opaque

## Project Context

This is an OPAQUE (RFC 9807) client library for TypeScript/JavaScript. It provides password-authenticated key exchange (PAKE) without the server ever seeing the password. Core cryptographic operations are compiled to WASM for performance and security.

## Code Review Guidelines

### Security (Critical)

- Flag any use of `Math.random()` — all randomness MUST use `crypto.getRandomValues()`.
- Flag hardcoded keys, secrets, or test credentials outside of `tests/` directory.
- Flag any operation that leaks password material (logging, error messages, stack traces).
- Verify constant-time comparisons for secret values — no early-return on mismatch.
- OPAQUE protocol flow must match RFC 9807 section references in comments.

### TypeScript Conventions

- Use `Uint8Array` for all binary data — never `Buffer` (this is a browser-compatible library).
- Prefer `.slice()` for defensive copies of `Uint8Array` — not spread (`[...arr]`).
- Prefer the `concat()` utility from `src/crypto/utils.ts` for joining `Uint8Array` — not spread.
- Use `@ts-expect-error` with issue reference for known TS 5.7+ `BufferSource` type mismatches — not `as unknown as` double casts.
- All exported functions must have JSDoc with `@param` and `@returns`.
- Async functions returning `Uint8Array` should use `Promise<Uint8Array>`, not `Promise<ArrayBuffer>`.

### Naming

- HKDF input parameter: `ikm` (Input Keying Material) — never `prk` (which implies extract already happened).
- OPRF functions: `oprfBlind`, `oprfFinalize`, `oprfEvaluate` — camelCase with `oprf` prefix.
- Test variables should match function parameter names for clarity.

### Testing

- Every public function must have unit tests covering happy path and error cases.
- Crypto tests must verify determinism (same input → same output) and uniqueness (different input → different output).
- Use `vitest` — not `jest`.
- Test file naming: `tests/unit/<module>.test.ts`.

### Commit Messages (Conventional Commits)

All commits MUST follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[(scope)]: <description>

[optional body]

[optional footer]
```

Valid types: `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`, `chore`, `style`.

Rules:
- Title: imperative mood, lowercase, no period, max 50 characters.
- Scope: optional, e.g. `crypto`, `oprf`, `ake`, `ci`.
- Body: explain WHAT and WHY, not HOW. Use bullet points.
- Footer: issue references (`Closes #N`).
- Breaking changes: `feat!:` or `BREAKING CHANGE:` in footer.

### Dependencies

- Zero runtime dependencies — only `devDependencies` for build/test tooling.
- WebCrypto API only — no Node.js `crypto` module imports.
- The library must work in browsers, Node.js, Deno, and Cloudflare Workers.

### What NOT to Flag

- `TODO` and `Placeholder` comments are intentional — this is scaffold-stage code.
- Reserved/unused parameters prefixed with `_` (e.g., `_serverId`) are protocol placeholders.
- Zero-filled salt in HKDF is a known placeholder, documented in comments.
