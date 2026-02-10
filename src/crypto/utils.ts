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
  return crypto.subtle.digest('SHA-256', data as unknown as BufferSource);
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
 * Derives key material from input keying material (IKM) with the given info string.
 * Uses WebCrypto's HKDF which performs extract+expand internally.
 */
export async function hkdfExpand(
  prk: Uint8Array,
  info: string,
  length: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    prk as unknown as BufferSource,
    { name: 'HKDF' },
    false,
    ['deriveBits'],
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32) as unknown as BufferSource,
      info: encode(info) as unknown as BufferSource,
    },
    key,
    length * 8,
  );

  return new Uint8Array(derived);
}
