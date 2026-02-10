import { concat, hash, hkdfDerive } from './utils';

export interface EnvelopeResult {
  envelope: Uint8Array;
  exportKey: Uint8Array;
}

/**
 * Build a credential envelope from the OPRF output.
 *
 * TODO: Replace with proper envelope construction per RFC 9807 Section 4.
 * Current implementation is a placeholder.
 */
export async function buildEnvelope(
  oprfOutput: Uint8Array,
  serverId: string,
): Promise<EnvelopeResult> {
  const info = new TextEncoder().encode(`OPAQUE-Envelope-${serverId}`);
  const ikm = new Uint8Array(await hash(concat(oprfOutput, info)));

  const envelopeKey = await hkdfDerive(ikm, 'envelope-key', 32);
  const exportKey = await hkdfDerive(ikm, 'export-key', 32);

  // Placeholder: envelope is the derived key material (no encryption yet)
  const envelope = envelopeKey.slice();

  return { envelope, exportKey };
}
