/**
 * Pins the browser demo verifier to the cross-verifier golden vector
 * (docs/testing/CROSS_VERIFIER_FIXTURES.md) — the same token the Java/Swift/Go suites verify —
 * and to the wire-strictness rules it shares with the real SDK verifiers: strict unpadded
 * base64url, the alg/crv/typ header pin before any signature work, the ver gate, and (new) the
 * FULL claim table plus a hand-rolled strict JSON parser (duplicate keys and non-integer/oversized
 * numbers rejected) — see grantmint-spring-boot-starter's StrictJson.java / OfflineTokenVerifier.java
 * and verifiers/go/grantmint_test.go's TestValidlySignedButNonStrictPayloadsAreMalformed, whose
 * adversarial vectors are ported below so the dashboard's demo verifier stays parity-honest with
 * the shipped SDKs.
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
  if (h === undefined || p === undefined || s === undefined) {
    throw new Error('fixture token must have 3 segments');
  }
  return [h, p, s];
}

function b64url(json: string): string {
  return Buffer.from(json, 'utf8').toString('base64url');
}

// ─── Test-side signer: WebCrypto Ed25519 over the raw fixture seed ────────────────────────────
//
// The same seed the Go/Swift parity suites embed (verifiers/go/grantmint_test.go's
// fixtureSeedHex) — reproduces the exact fixture public key above. WebCrypto's Ed25519 "raw"
// import format is verify-only for a public key; signing needs the seed wrapped in a minimal
// PKCS8 DER envelope (RFC 8410's fixed prefix for a 32-byte Ed25519 seed).
const FIXTURE_SEED_HEX = '52ec811207633ad9f4a283d8eb887630e6183f7b6dfa8ea02fc4b9f9c7438aec'; // gitleaks:allow — published golden vector seed, not a credential
const PKCS8_ED25519_SEED_PREFIX_HEX = '302e020100300506032b657004220420';

async function signRaw(headerJson: string, payloadJson: string): Promise<string> {
  const pkcs8 = Buffer.concat([
    Buffer.from(PKCS8_ED25519_SEED_PREFIX_HEX, 'hex'),
    Buffer.from(FIXTURE_SEED_HEX, 'hex'),
  ]);
  const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  const headerSeg = b64url(headerJson);
  const payloadSeg = b64url(payloadJson);
  const signingInput = new TextEncoder().encode(`${headerSeg}.${payloadSeg}`);
  const signature = await crypto.subtle.sign('Ed25519', key, signingInput);
  const sigSeg = Buffer.from(signature).toString('base64url');
  return `${headerSeg}.${payloadSeg}.${sigSeg}`;
}

const PINNED_HEADER_JSON = '{"alg":"EdDSA","crv":"Ed25519","kid":"GMK1","typ":"GMT"}';
// requiredTail carries every required claim except exp and ver, so each adversarial case below
// isolates exactly one defect (mirrors the Go/Swift/starter parity suites).
const REQUIRED_TAIL = '"ent":{},"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p"';

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
    const value = BASE64URL_ALPHABET.indexOf(last ?? '');
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

  // ─── Validly-signed but non-strict payloads: parity with Go's
  // TestValidlySignedButNonStrictPayloadsAreMalformed (including the seat-beyond-int32,
  // boolean-ver, and ent-array-value cases added there) ──────────────────────────────────────────
  //
  // Every payload below is signed for real with the fixture seed, so the signature check passes —
  // isolating exactly the claim-table / strict-JSON defect under test. Before this fix, F2/F3 meant
  // some of these (a string/missing exp, a float, a duplicate key) would have rendered "VALID".
  describe('rejects validly-signed but non-strict payloads as malformed', () => {
    const cases: Record<string, string> = {
      'duplicate key': `{"exp":null,"exp":null,${REQUIRED_TAIL},"ver":1}`,
      'float exp': `{"exp":1.5,${REQUIRED_TAIL},"ver":1}`,
      'exponent number': `{"exp":2e9,${REQUIRED_TAIL},"ver":1}`,
      'oversized integer': `{"exp":99999999999999999999,${REQUIRED_TAIL},"ver":1}`,
      'string exp': `{"exp":"1782666000",${REQUIRED_TAIL},"ver":1}`,
      'missing exp': `{${REQUIRED_TAIL},"ver":1}`,
      'trailing content': `{"exp":null,${REQUIRED_TAIL},"ver":1} {}`,
      // A ver beyond int32 is a malformed claim (the reference parses ver as an int), NOT a future
      // format version — only a well-typed in-range unknown version gets its own reason below.
      'ver beyond int32': `{"exp":null,${REQUIRED_TAIL},"ver":5000000000}`,
      'non-object toplevel': '[1,2,3]',
      'missing pol/hld/iat': '{"ent":{},"exp":null,"kid":"K","lid":"l","prd":"p","ver":1}',
      'missing ent': '{"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}',
      'ent not an object':
        '{"ent":42,"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}',
      'empty prd':
        '{"ent":{},"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"","ver":1}',
      'empty holder email':
        '{"ent":{},"exp":null,"hld":{"e":"","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}',
      'con not an object': `{"con":7,"exp":null,${REQUIRED_TAIL},"ver":1}`,
      'seat not an integer': `{"exp":null,${REQUIRED_TAIL},"seat":"two","ver":1}`,
      // seat is an int in the claim table; the reference parses it with Math.toIntExact, so an
      // int64 outside the 32-bit range is malformed there and must be malformed here too.
      'seat beyond int32': `{"exp":null,${REQUIRED_TAIL},"seat":5000000000,"ver":1}`,
      'seat beyond negative int32': `{"exp":null,${REQUIRED_TAIL},"seat":-5000000000,"ver":1}`,
      // Adversarial shapes the Swift suite pins that Go is structurally immune to (encoding/json
      // yields distinct types) — pinned anyway so every suite asserts the same vectors.
      'boolean ver': `{"exp":null,${REQUIRED_TAIL},"ver":true}`,
      'ent array value':
        '{"ent":{"tier":[1,2]},"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}',
    };

    for (const [name, payloadJson] of Object.entries(cases)) {
      it(`rejects: ${name}`, async () => {
        const token = await signRaw(PINNED_HEADER_JSON, payloadJson);
        await expect(verifyTokenOffline(token, PUBLIC_KEY_BASE64, IAT)).rejects.toThrow(TokenFormatError);
      });
    }
  });

  it('rejects an unknown format version with its own distinct reason', async () => {
    // 2026-07-05 audit (GRANTMINT-148): an authentic token from a future format version keeps the
    // Java verifiers' distinct UNSUPPORTED_VERSION reason — still rejected, but telemetry can tell
    // "update the verifier" apart from a corrupt token.
    const token = await signRaw(PINNED_HEADER_JSON, `{"exp":null,${REQUIRED_TAIL},"ver":2}`);
    await expect(verifyTokenOffline(token, PUBLIC_KEY_BASE64, IAT)).rejects.toMatchObject({
      reason: 'unsupported_version',
    });
  });

  it('carries the alg/typ pin reasons distinctly, defaulting everything else to malformed', async () => {
    const payload = `{"exp":null,${REQUIRED_TAIL},"ver":1}`;
    const algConfused = await signRaw(
      '{"alg":"none","crv":"Ed25519","kid":"GMK1","typ":"GMT"}',
      payload,
    );
    await expect(verifyTokenOffline(algConfused, PUBLIC_KEY_BASE64, IAT)).rejects.toMatchObject({
      reason: 'alg_not_allowed',
    });
    const foreignType = await signRaw(
      '{"alg":"EdDSA","crv":"Ed25519","kid":"GMK1","typ":"JWT"}',
      payload,
    );
    await expect(verifyTokenOffline(foreignType, PUBLIC_KEY_BASE64, IAT)).rejects.toMatchObject({
      reason: 'wrong_type',
    });
    const missingEnt = await signRaw(
      PINNED_HEADER_JSON,
      '{"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}',
    );
    await expect(verifyTokenOffline(missingEnt, PUBLIC_KEY_BASE64, IAT)).rejects.toMatchObject({
      reason: 'malformed',
    });
  });

  it('rejects a header missing kid even when validly signed', async () => {
    // Parity with the starter/Go TestHeaderMissingKidIsMalformed: the reference decodeHeader
    // requires all four header fields as strings; a validly-signed token whose header drops kid
    // must be malformed too, not just the tampered-header variant above.
    const token = await signRaw(
      '{"alg":"EdDSA","crv":"Ed25519","typ":"GMT"}',
      `{"exp":null,${REQUIRED_TAIL},"ver":1}`,
    );
    await expect(verifyTokenOffline(token, PUBLIC_KEY_BASE64, IAT)).rejects.toThrow(TokenFormatError);
  });

  it('accepts a validly-signed perpetual (null exp) token far in the future', async () => {
    const token = await signRaw(PINNED_HEADER_JSON, `{"exp":null,${REQUIRED_TAIL},"ver":1}`);
    const result = await verifyTokenOffline(token, PUBLIC_KEY_BASE64, 4102444800); // year 2100
    expect(result.signatureValid).toBe(true);
    expect(result.expired).toBe(false);
  });

  it('enforces the nbf gate (inclusive) on a validly-signed token', async () => {
    const token = await signRaw(PINNED_HEADER_JSON, `{"exp":null,${REQUIRED_TAIL},"nbf":1000,"ver":1}`);
    const before = await verifyTokenOffline(token, PUBLIC_KEY_BASE64, 999);
    expect(before.notYetValid).toBe(true);
    const atNbf = await verifyTokenOffline(token, PUBLIC_KEY_BASE64, 1000);
    expect(atNbf.notYetValid).toBe(false);
  });
});
