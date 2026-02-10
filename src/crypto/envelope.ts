import { hash, hkdfExpand } from './utils';

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
  const prk = new Uint8Array(await hash(new Uint8Array([...oprfOutput, ...info])));

  const envelopeKey = await hkdfExpand(prk, 'envelope-key', 32);
  const exportKey = await hkdfExpand(prk, 'export-key', 32);

  // Placeholder: envelope is just the encrypted key material
  const envelope = new Uint8Array([...envelopeKey]);

  return { envelope, exportKey };
}
