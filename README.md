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

## Status

Early development. Crypto modules are placeholders using WebCrypto HKDF/SHA-256. Full OPAQUE implementation with ristretto255 and 3DH AKE will be added via WASM.

## License

Apache-2.0
