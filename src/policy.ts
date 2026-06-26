/**
 * Password-policy validation — pure-TS, byte-for-byte equivalent to the Rust
 * `sid_crypto::policy::validate_password_client_side` (the JS fallback used when
 * WASM is unavailable). This is the *validation* gadget (gadget A logic) only;
 * the zero-knowledge proof of compliance is WASM/Halo2-only (pure-TS Halo2 is
 * ~500s and not viable), so no-WASM clients send policy-validated input that the
 * server re-checks rather than a ZK proof.
 *
 * Apples-to-apples requirements vs the Rust reference:
 *   - length = UTF-8 BYTE length (Rust `str::len()`), not char count
 *   - char classes via Unicode scalar iteration: A–Z, a–z, 0–9, and "symbol" =
 *     anything else that is not ASCII whitespace (`!char::is_ascii_whitespace`)
 *   - identical error message strings
 */

/** Mirrors `sid_pake_core::types::PolicyParams`. */
export interface PolicyParams {
  minLength: number;
  minUpper: number;
  minLower: number;
  minDigit: number;
  minSymbol: number;
}

/** Mirrors `sid_pake_core::types::CE_DEFAULT_POLICY` (NIST SP 800-63B baseline). */
export const CE_DEFAULT_POLICY: PolicyParams = {
  minLength: 8,
  minUpper: 1,
  minLower: 1,
  minDigit: 1,
  minSymbol: 0,
};

/** Mirrors `sid_crypto::policy::CE_POLICY_VERSION`. */
export const CE_POLICY_VERSION = 1;

const _utf8 = new TextEncoder();

/** ASCII whitespace per Rust `char::is_ascii_whitespace`: space, \t, \n, \f, \r. */
function isAsciiWhitespace(cp: number): boolean {
  return cp === 0x20 || cp === 0x09 || cp === 0x0a || cp === 0x0c || cp === 0x0d;
}

/** Mirrors `sid_crypto::policy::get_policy`. */
export function getPolicy(version: number): PolicyParams | null {
  switch (version) {
    case 1:
      return CE_DEFAULT_POLICY;
    default:
      return null;
  }
}

/**
 * Validate `password` against `policy`, returning human-readable error strings
 * (empty = compliant). Byte-for-byte equivalent to the Rust reference.
 */
export function validatePasswordClientSide(password: string, policy: PolicyParams): string[] {
  const errors: string[] = [];
  const len = _utf8.encode(password).length; // UTF-8 byte length == Rust str::len()

  if (len < policy.minLength) {
    errors.push(`Password too short: minimum ${policy.minLength} characters, got ${len}`);
  }

  let upper = 0;
  let lower = 0;
  let digit = 0;
  let symbol = 0;
  for (const ch of password) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0x41 && cp <= 0x5a) upper++; // A–Z
    else if (cp >= 0x61 && cp <= 0x7a) lower++; // a–z
    else if (cp >= 0x30 && cp <= 0x39) digit++; // 0–9
    else if (!isAsciiWhitespace(cp)) symbol++; // everything else (non-whitespace)
  }

  if (upper < policy.minUpper) {
    errors.push(`Need at least ${policy.minUpper} uppercase letters, got ${upper}`);
  }
  if (lower < policy.minLower) {
    errors.push(`Need at least ${policy.minLower} lowercase letters, got ${lower}`);
  }
  if (digit < policy.minDigit) {
    errors.push(`Need at least ${policy.minDigit} digits, got ${digit}`);
  }
  if (symbol < policy.minSymbol) {
    errors.push(`Need at least ${policy.minSymbol} symbols, got ${symbol}`);
  }

  return errors;
}
