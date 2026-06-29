/**
 * Minimal OPAQUE test server.
 *
 * Implements server-side OPAQUE protocol over HTTP for local testing.
 * Uses in-memory storage for registration records.
 *
 * Endpoints:
 *   POST /register/init    — OPRF blind evaluate + return server public key
 *   POST /register/finish  — Store registration record
 *   POST /login/init       — OPRF evaluate + KE2
 *   POST /login/finish     — Verify KE3, return session confirmation
 *   GET  /health           — Health check
 *
 * Usage:
 *   SUITE=P256_SHA256 PORT=8080 npx tsx tests/server/index.ts
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { CipherSuiteId, getSuite, type CipherSuite } from '../../src/suites.js';
import { getGroup } from '../../src/group/index.js';
import { oprfBlindEvaluate, oprfGenerateKeyPair, type OprfKeyPair } from '../../src/oprf.js';
import { maskResponse, deserializeEnvelope, envelopeSize } from '../../src/key-schedule.js';
import {
  serverAkeRespond,
  serverAkeFinish,
  serializeKE2,
  type ServerAkeState,
} from '../../src/ake.js';

const PORT = parseInt(process.env.PORT ?? '8080', 10);
const SUITE_NAME = process.env.SUITE ?? 'P256_SHA256';

// ── Resolve suite from env ──

function _resolveSuiteId(name: string): CipherSuiteId {
  const map: Record<string, CipherSuiteId> = {
    RISTRETTO255_SHA512: CipherSuiteId.RISTRETTO255_SHA512,
    P256_SHA256: CipherSuiteId.P256_SHA256,
    P384_SHA384: CipherSuiteId.P384_SHA384,
    P521_SHA512: CipherSuiteId.P521_SHA512,
  };
  const id = map[name];
  if (id === undefined)
    throw new Error(`Unknown suite: ${name}. Valid: ${Object.keys(map).join(', ')}`);
  return id;
}

// ── Server state ──

interface RegistrationRecord {
  clientPublicKey: Uint8Array;
  maskingKey: Uint8Array;
  envelopeNonce: Uint8Array;
  envelopeAuthTag: Uint8Array;
}

interface ServerConfig {
  suite: CipherSuite;
  oprfKp: OprfKeyPair;
  serverKp: { secretKey: Uint8Array; publicKey: Uint8Array };
}

// Per-suite server config
const configs = new Map<CipherSuiteId, ServerConfig>();
// Registration records: clientId → record
const records = new Map<string, RegistrationRecord>();
// Login sessions: clientId → server AKE state (waiting for KE3)
const loginSessions = new Map<string, ServerAkeState>();

function getConfig(suiteId: CipherSuiteId): ServerConfig {
  let config = configs.get(suiteId);
  if (!config) {
    const suite = getSuite(suiteId);
    const group = getGroup(suite.curve);
    config = {
      suite,
      oprfKp: oprfGenerateKeyPair(suite.curve),
      serverKp: group.generateKeypair(),
    };
    configs.set(suiteId, config);
  }
  return config;
}

// ── Helpers ──

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function json(res: ServerResponse, status: number, data: unknown): void {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function b64(arr: Uint8Array): string {
  return Buffer.from(arr).toString('base64');
}

function unb64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

// ── Route handlers ──

async function handleRegisterInit(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = JSON.parse((await readBody(req)).toString());
  const suiteId: CipherSuiteId = body.suite;
  const blindedElement = unb64(body.blindedElement);

  const config = getConfig(suiteId);
  const evaluated = oprfBlindEvaluate(config.suite.curve, config.oprfKp.secretKey, blindedElement);

  json(res, 200, {
    evaluatedElement: b64(evaluated),
    serverPublicKey: b64(config.serverKp.publicKey),
  });
}

async function handleRegisterFinish(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = JSON.parse((await readBody(req)).toString());
  const clientId: string = body.clientId;
  const suiteId: CipherSuiteId = body.suite;
  const record = unb64(body.record);

  const config = getConfig(suiteId);
  const suite = config.suite;

  // Parse registration record: clientPublicKey(Npk) || maskingKey(Nh) || envelope(Nn + Nm)
  let offset = 0;
  const clientPublicKey = record.slice(offset, offset + suite.elementSize);
  offset += suite.elementSize;
  const maskingKey = record.slice(offset, offset + suite.oprfOutputSize);
  offset += suite.oprfOutputSize;
  const envSize = envelopeSize(suite);
  const envelopeBytes = record.slice(offset, offset + envSize);
  const envelope = deserializeEnvelope(envelopeBytes, suite);

  records.set(clientId, {
    clientPublicKey,
    maskingKey,
    envelopeNonce: envelope.nonce,
    envelopeAuthTag: envelope.authTag,
  });

  json(res, 200, { ok: true });
}

async function handleLoginInit(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = JSON.parse((await readBody(req)).toString());
  const clientId: string = body.clientId;
  const suiteId: CipherSuiteId = body.suite;
  const ke1Bytes = unb64(body.ke1);

  const config = getConfig(suiteId);
  const suite = config.suite;

  // Look up registration record
  const rec = records.get(clientId);
  if (!rec) {
    json(res, 404, { error: 'User not registered' });
    return;
  }

  // OPRF blind evaluate
  const blindedElement = ke1Bytes.slice(0, suite.elementSize);
  const evaluated = oprfBlindEvaluate(suite.curve, config.oprfKp.secretKey, blindedElement);

  // Build credential response: evaluated || masking_nonce || masked_response
  const envelope = { nonce: rec.envelopeNonce, authTag: rec.envelopeAuthTag };
  const { maskingNonce, maskedResponse } = maskResponse(
    rec.maskingKey,
    config.serverKp.publicKey,
    envelope,
    suite,
  );

  const credentialResponse = new Uint8Array(
    suite.elementSize + suite.nonceSize + maskedResponse.length,
  );
  credentialResponse.set(evaluated, 0);
  credentialResponse.set(maskingNonce, suite.elementSize);
  credentialResponse.set(maskedResponse, suite.elementSize + suite.nonceSize);

  // Parse KE1 components
  let offset = 0;
  const credentialRequest = ke1Bytes.slice(offset, offset + suite.elementSize);
  offset += suite.elementSize;
  const clientNonce = ke1Bytes.slice(offset, offset + suite.nonceSize);
  offset += suite.nonceSize;
  const clientPublicKeyshare = ke1Bytes.slice(offset, offset + suite.elementSize);

  const ke1 = { credentialRequest, clientNonce, clientPublicKeyshare };

  const clientIdBytes = new TextEncoder().encode(clientId);
  const serverIdBytes = new TextEncoder().encode(process.env.SERVER_ID ?? 'sid.example.com');

  // Server AKE respond
  const { ke2, state } = serverAkeRespond(
    config.serverKp.secretKey,
    config.serverKp.publicKey,
    rec.clientPublicKey,
    credentialResponse,
    ke1,
    clientIdBytes,
    serverIdBytes,
    suite,
  );

  loginSessions.set(clientId, state);

  const ke2Bytes = serializeKE2(ke2);
  json(res, 200, { ke2: b64(ke2Bytes) });
}

async function handleLoginFinish(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = JSON.parse((await readBody(req)).toString());
  const clientId: string = body.clientId;
  const ke3 = unb64(body.ke3);

  const state = loginSessions.get(clientId);
  if (!state) {
    json(res, 400, { error: 'No pending login session' });
    return;
  }

  try {
    const sessionKey = serverAkeFinish(ke3, state);
    loginSessions.delete(clientId);
    json(res, 200, { ok: true, sessionKeyHash: b64(sessionKey.slice(0, 8)) });
  } catch (e) {
    loginSessions.delete(clientId);
    json(res, 401, { error: (e as Error).message });
  }
}

// ── Router ──

const server = createServer(async (req, res) => {
  try {
    const url = req.url ?? '/';
    const method = req.method ?? 'GET';

    if (method === 'GET' && url === '/health') {
      json(res, 200, { status: 'ok', suites: Array.from(configs.keys()) });
      return;
    }

    if (method === 'POST') {
      switch (url) {
        case '/register/init':
          await handleRegisterInit(req, res);
          return;
        case '/register/finish':
          await handleRegisterFinish(req, res);
          return;
        case '/login/init':
          await handleLoginInit(req, res);
          return;
        case '/login/finish':
          await handleLoginFinish(req, res);
          return;
      }
    }

    json(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error('Request error:', err);
    json(res, 500, { error: (err as Error).message });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`OPAQUE test server listening on :${PORT}`);
  console.log(`Default suite: ${SUITE_NAME}`);
  console.log(`Server ID: ${process.env.SERVER_ID ?? 'sid.example.com'}`);
});
