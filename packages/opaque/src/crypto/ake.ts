import { concat, encode, hash, hkdfDerive } from './utils';

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
 *
 * @param oprfOutput - OPRF output bytes.
 * @param serverId - Server identity string for domain separation.
 * @returns Session key, export key, and finalization message.
 */
export async function deriveKeys(oprfOutput: Uint8Array, serverId: string): Promise<AkeResult> {
  const info = encode(`OPAQUE-AKE-${serverId}`);
  const ikm = await hash(concat(oprfOutput, info));

  const sessionKey = await hkdfDerive(ikm, 'session-key', 32);
  const exportKey = await hkdfDerive(ikm, 'export-key', 32);
  const finalization = await hkdfDerive(ikm, 'finalization', 32);

  return { sessionKey, exportKey, finalization };
}
