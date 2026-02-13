# @structured-id/opaque

[![CI/CD](https://github.com/structured-id/opaque/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/structured-id/opaque/actions/workflows/ci-cd.yml)
[![codecov](https://codecov.io/gh/structured-id/opaque/graph/badge.svg?token=923LHCL7KN)](https://codecov.io/gh/structured-id/opaque)
[![npm](https://img.shields.io/npm/v/@structured-id/opaque)](https://www.npmjs.com/package/@structured-id/opaque)

OPAQUE (RFC 9807) client library for browser and Node.js environments.

## Installation

```bash
npm install @structured-id/opaque
```

## Usage

```typescript
import { OpaqueClient } from '@structured-id/opaque';

const client = new OpaqueClient({ serverId: 'auth.example.com' });

// Registration
const reg = await client.registrationStart(password);
// Send `reg.request` to server, receive `serverResponse`
const { record, exportKey } = await client.registrationFinish(password, serverResponse, reg.state);

// Login
const login = await client.loginStart(password);
// Send `login.request` to server, receive `serverResponse`
const { finalization, sessionKey, exportKey: loginExportKey } = await client.loginFinish(
  password,
  serverResponse,
  login.state,
);
```

## Features

- **RFC 9807 OPAQUE** — Standard password-authenticated key exchange (PAKE)
- **Zero-Knowledge Password Policy (ZKPP)** — Cryptographic proof that password meets policy constraints without revealing the password
- **WASM support** — Core cryptographic operations compiled to WASM binary for performance and security
- **Fallback support** — Systems without WASM support fall back to standard RFC 9807

## Status

> **Production-ready for RFC 9807.** WASM-compiled core crypto operations require modern browsers with WebAssembly support.

## License

Apache-2.0
