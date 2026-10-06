/** Byte helpers shared by the OPAQUE client. */

const encoder = new TextEncoder();

export const utf8 = (s: string): Uint8Array => encoder.encode(s);

export function concat(parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const p of parts) length += p.length;
  const out = new Uint8Array(length);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** I2OSP(n, 2): big-endian, refusing values that do not fit. */
export function i2osp2(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff)
    throw new Error("i2osp: value does not fit two bytes");
  return Uint8Array.of(n >> 8, n & 0xff);
}

/** Constant-time equality of two byte strings of equal length. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** A reader that takes fixed-length fields off the front of a message. */
export class Reader {
  private at = 0;
  constructor(
    private readonly bytes: Uint8Array,
    private readonly what: string,
  ) {}

  take(length: number): Uint8Array {
    if (this.at + length > this.bytes.length)
      throw new Error(`${this.what}: too short`);
    const out = this.bytes.slice(this.at, this.at + length);
    this.at += length;
    return out;
  }

  /** Every byte must have been read. */
  end(): void {
    if (this.at !== this.bytes.length)
      throw new Error(`${this.what}: trailing bytes`);
  }
}

export function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function fromBase64(value: string, what: string): Uint8Array {
  let bin: string;
  try {
    bin = atob(value);
  } catch {
    throw new Error(`${what}: invalid base64`);
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
