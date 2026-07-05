/**
 * Pins the browser demo verifier to the cross-verifier golden vector
 * (docs/testing/CROSS_VERIFIER_FIXTURES.md) — the same token the Java/Swift/Go suites verify —
 * and to the wire-strictness rules it shares with the real SDK verifiers: strict unpadded
 * base64url, the alg/crv/typ header pin before any signature work, and the ver gate.
 *
 * Runs under Node's WebCrypto (Ed25519 supported since Node 20); vitest's default environment
 * provides `crypto`, `atob`, `TextEncoder`, and `TextDecoder`.
 */
import { describe, expect, it } from 'vitest';

import { TokenFormatError, verifyTokenOffline } from './tokenVerify';

// The published golden vector — a TEST fixture, not a credential.
const PUBLIC_KEY_HEX = '34687417cc2f326d57e0a3702bb8bafda49bf8bdbb9f9ed224d0e0deb8be4101';
const PUBLIC_KEY_BASE64 = Buffer.from(PUBLIC_KEY_HEX, 'hex').toString('base64');
const IAT = 1751130000;
const EXP = 1782666000;
const TOKEN =
  'eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJHTUsxIiwidHlwIjoiR01UIn0.' + // gitleaks:allow — published golden vector
  'eyJjb24iOnsibm9kZUxvY2tlZCI6dHJ1ZSwic2VhdHMiOjJ9LCJlbnQiOnsiYWlfYXNzaXN0Ijp0cnVlLCJtYXhfZGV2aWNlcyI6MiwibWF4X3Byb2plY3RzIjoxMCwidGVhbV9zeW5jIjp0cnVlLCJ0aWVyIjoicHJvIn0sImV4cCI6MTc4MjY2NjAwMCwiaGxkIjp7ImUiOiJqYW5lQGV4YW1wbGUuY29tIiwibiI6IkphbmUgRG9lIn0sImlhdCI6MTc1MTEzMDAwMCwia2lkIjoiSzdQMi05UVhNLTRUMUEiLCJsaWQiOiJsaWNfMDFKWjhYOVE0UjdNMkszUDVUNlY4VzBZMkEiLCJwb2wiOiJwb2xfcHJvX2FubnVhbCIsInByZCI6InByb2RfYWNtZV9ub3RlcyIsInNlYXQiOjIsInZlciI6MX0.' +
  'dE2gDMZMeggftOMOeLjAK3fOu5Ax8b9DKSYSGb0N7pWoUZbZ43jdMRzrNTuQ734MsBGmFEi5bDoCFpJ0js8zDg';

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function segments(): [string, string, string] {
  const [h, p, s] = TOKEN.split('.');
  return [h, p, s];
}

function b64url(json: string): string {
  return Buffer.from(json, 'utf8').toString('base64url');
}

describe('verifyTokenOffline', () => {
  it('verifies the pinned cross-verifier vector with its exact claims', async () => {
    const result = await verifyTokenOffline(TOKEN, PUBLIC_KEY_BASE64, IAT);
    expect(result.signatureValid).toBe(true);
    expect(result.expired).toBe(false);
    expect(result.notYetValid).toBe(false);
    expect(result.header.kid).toBe('GMK1');
    expect(result.payload.kid).toBe('K7P2-9QXM-4T1A');
    expect(result.payload.prd).toBe('prod_acme_notes');
    expect(result.payload.exp).toBe(EXP);
    expect(result.payload.ent).toMatchObject({ team_sync: true, max_devices: 2, tier: 'pro' });
  });

  it('reports expired at exactly exp (exclusive) but not one second before', async () => {
    const atExp = await verifyTokenOffline(TOKEN, PUBLIC_KEY_BASE64, EXP);
    expect(atExp.signatureValid).toBe(true);
    expect(atExp.expired).toBe(true);
    const justBefore = await verifyTokenOffline(TOKEN, PUBLIC_KEY_BASE64, EXP - 1);
    expect(justBefore.expired).toBe(false);
  });

  it('rejects a padded segment', async () => {
    const [h, p, s] = segments();
    await expect(verifyTokenOffline(`${h}=.${p}.${s}`, PUBLIC_KEY_BASE64, IAT)).rejects.toThrow(
      TokenFormatError,
    );
  });

  it('rejects a standard-alphabet character in a segment', async () => {
    const [h, p, s] = segments();
    await expect(verifyTokenOffline(`${h}.${p}.+${s.slice(1)}`, PUBLIC_KEY_BASE64, IAT)).rejects.toThrow(
      TokenFormatError,
    );
  });

  it('rejects every non-canonical spelling of the signature segment', async () => {
    // The 86-char signature leaves 4 unused trailing bits: 15 alternate spellings decode to the
    // SAME bytes. One text form per byte string — all 15 must be malformed.
    const last = TOKEN[TOKEN.length - 1];
    const value = BASE64URL_ALPHABET.indexOf(last);
    expect(value % 16).toBe(0);
    for (let bits = 1; bits <= 15; bits += 1) {
      const spelled = TOKEN.slice(0, -1) + BASE64URL_ALPHABET[value | bits];
      await expect(verifyTokenOffline(spelled, PUBLIC_KEY_BASE64, IAT)).rejects.toThrow(TokenFormatError);
    }
  });

  it('rejects alg confusion before any signature work', async () => {
    const [, p] = segments();
    const noneHeader = b64url('{"alg":"none","crv":"Ed25519","kid":"GMK1","typ":"GMT"}');
    const garbageSig = Buffer.alloc(64).toString('base64url');
    await expect(
      verifyTokenOffline(`${noneHeader}.${p}.${garbageSig}`, PUBLIC_KEY_BASE64, IAT),
    ).rejects.toThrow(TokenFormatError);
  });

  it('rejects a kid-less header', async () => {
    const [, p, s] = segments();
    const kidless = b64url('{"alg":"EdDSA","crv":"Ed25519","typ":"GMT"}');
    await expect(verifyTokenOffline(`${kidless}.${p}.${s}`, PUBLIC_KEY_BASE64, IAT)).rejects.toThrow(
      TokenFormatError,
    );
  });

  it('fails closed on an unknown format version before the signature', async () => {
    const [h, , s] = segments();
    const versionTwo = b64url('{"exp":null,"ver":2}');
    await expect(verifyTokenOffline(`${h}.${versionTwo}.${s}`, PUBLIC_KEY_BASE64, IAT)).rejects.toThrow(
      TokenFormatError,
    );
  });

  it('reports signatureValid=false for a substituted payload', async () => {
    const [h, , s] = segments();
    const forged = b64url('{"exp":null,"ver":1}');
    const result = await verifyTokenOffline(`${h}.${forged}.${s}`, PUBLIC_KEY_BASE64, IAT);
    expect(result.signatureValid).toBe(false);
  });

  it('rejects wrong segment counts', async () => {
    await expect(verifyTokenOffline('a.b', PUBLIC_KEY_BASE64, IAT)).rejects.toThrow(TokenFormatError);
    await expect(verifyTokenOffline(`${TOKEN}.extra`, PUBLIC_KEY_BASE64, IAT)).rejects.toThrow(
      TokenFormatError,
    );
  });
});
