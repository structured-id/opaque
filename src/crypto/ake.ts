import { hash, hkdfExpand } from './utils';

export interface AkeResult {
  sessionKey: Uint8Array;
  exportKey: Uint8Array;
  finalization: Uint8Array;
}

/**
 * Derive session and export keys from OPRF output.
 *
 * TODO: Replace with proper 3DH AKE when full implementation is ready.
 * Current implementation uses HKDF as placeholder.
 */
export async function deriveKeys(oprfOutput: Uint8Array, serverId: string): Promise<AkeResult> {
  const info = new TextEncoder().encode(`OPAQUE-AKE-${serverId}`);
  const prk = new Uint8Array(await hash(new Uint8Array([...oprfOutput, ...info])));

  const sessionKey = await hkdfExpand(prk, 'session-key', 32);
  const exportKey = await hkdfExpand(prk, 'export-key', 32);
  const finalization = await hkdfExpand(prk, 'finalization', 32);

  return { sessionKey, exportKey, finalization };
}
