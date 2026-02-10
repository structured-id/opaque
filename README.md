# @structured-id/opaque

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
const { request, state } = await client.registrationStart(password);
// Send `request` to server, receive `serverResponse`
const { record, exportKey } = await client.registrationFinish(password, serverResponse, state);

// Login
const { request, state } = await client.loginStart(password);
// Send `request` to server, receive `serverResponse`
const { finalization, sessionKey, exportKey } = await client.loginFinish(password, serverResponse, state);
```

## Status

Early development. Crypto modules are placeholders using WebCrypto HKDF/SHA-256. Full OPAQUE implementation with ristretto255 and 3DH AKE will be added via WASM.

## License

Apache-2.0
