// Apples-to-apples parity test: TS validatePasswordClientSide vs the Rust
// reference `sid_crypto::policy::validate_password_client_side`. Expected error
// strings are derived from the Rust logic (byte length, char-class counts,
// identical messages). Any divergence = the TS lags the Rust.
import { describe, it, expect } from 'vitest';
import {
  validatePasswordClientSide,
  CE_DEFAULT_POLICY,
  getPolicy,
  type PolicyParams,
} from '../src/policy.js';

const P = CE_DEFAULT_POLICY; // 8 / 1 / 1 / 1 / 0

describe('validatePasswordClientSide — parity with Rust reference', () => {
  it('compliant password → no errors', () => {
    expect(validatePasswordClientSide('HrenVamSID12!', P)).toEqual([]);
    expect(validatePasswordClientSide('Abcdefg1', P)).toEqual([]); // exactly minLength 8
  });

  it('too short → exact Rust message with byte length', () => {
    expect(validatePasswordClientSide('Ab1', P)).toEqual([
      'Password too short: minimum 8 characters, got 3',
    ]);
  });

  it('missing each class → exact Rust messages, counts reported', () => {
    // all lowercase, length ok → missing upper + digit
    expect(validatePasswordClientSide('abcdefghij', P)).toEqual([
      'Need at least 1 uppercase letters, got 0',
      'Need at least 1 digits, got 0',
    ]);
    // no lowercase
    expect(validatePasswordClientSide('ABCDEFG1', P)).toEqual([
      'Need at least 1 lowercase letters, got 0',
    ]);
  });

  it('symbol class counts non-ASCII-whitespace (matches !is_ascii_whitespace)', () => {
    const policy: PolicyParams = { ...P, minSymbol: 2 };
    // "Ab1!§" → symbols: '!' and '§' (non-ascii) = 2
    expect(validatePasswordClientSide('Abcde1!§', policy)).toEqual([]);
    // only one symbol → error reporting count
    expect(validatePasswordClientSide('Abcdef1!', policy)).toEqual([
      'Need at least 2 symbols, got 1',
    ]);
  });

  it('length is UTF-8 BYTE length, not char count (Rust str::len)', () => {
    // "Aä1" = A(1) ä(2 bytes) 1(1) = 4 bytes, 3 chars; minLength 5 → too short, got 4
    expect(validatePasswordClientSide('Aä1', { ...P, minLength: 5 })).toContain(
      'Password too short: minimum 5 characters, got 4',
    );
  });

  it('getPolicy mirrors Rust versions', () => {
    expect(getPolicy(1)).toEqual(CE_DEFAULT_POLICY);
    expect(getPolicy(99)).toBeNull();
  });
});
