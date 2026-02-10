const encoder = new TextEncoder();

/** Encode a string to UTF-8 bytes. */
export function encode(input: string): Uint8Array {
  return encoder.encode(input);
}

/** Generate cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** SHA-256 hash. */
export async function hash(data: Uint8Array): Promise<ArrayBuffer> {
  // @ts-expect-error TS 5.7+ Uint8Array<ArrayBufferLike> vs BufferSource mismatch (microsoft/TypeScript#59451)
  return crypto.subtle.digest('SHA-256', data);
}

/** Concatenate multiple Uint8Arrays. */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * HKDF key derivation using WebCrypto.
 *
 * Uses WebCrypto's HKDF which performs both extract and expand internally.
 * The `ikm` parameter is input keying material (NOT a pre-extracted PRK).
 * A zero-filled salt is used for the extract step — this is placeholder
 * behavior and will be replaced with proper salt handling in the WASM
 * implementation.
 *
 * Note: This is NOT equivalent to RFC 5869 HKDF-Expand alone.
 */
export async function hkdfDerive(
  ikm: Uint8Array,
  info: string,
  length: number,
): Promise<Uint8Array> {
  // @ts-expect-error TS 5.7+ Uint8Array<ArrayBufferLike> vs BufferSource mismatch (microsoft/TypeScript#59451)
  const key = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);

  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      // Placeholder: zero salt — will use proper salt in WASM implementation
      salt: new Uint8Array(32),
      // @ts-expect-error TS 5.7+ Uint8Array<ArrayBufferLike> vs BufferSource mismatch
      info: encode(info),
    },
    key,
    length * 8,
  );

  return new Uint8Array(derived);
}
