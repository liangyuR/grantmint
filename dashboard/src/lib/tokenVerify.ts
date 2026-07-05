/**
 * Browser-side OFFLINE verification of a Grantmint signed token, reproducing exactly what
 * grantmint-core's LicenseVerifier does server-side (docs/features/LICENSE_TOKEN_FORMAT.md):
 *
 *   token         = base64url(header) "." base64url(payload) "." base64url(signature)
 *   signingInput  = ASCII bytes of "<headerSegment>.<payloadSegment>" (the RECEIVED segments,
 *                   never a re-serialization)
 *   signature     = 64-byte Ed25519 signature over signingInput, base64url-encoded
 *
 * This is a demo-page convenience for showing "verification needs no network," NOT a general
 * client SDK — but it enforces the same wire strictness as the real verifiers where it counts:
 * token segments are STRICT unpadded base64url (padding, the standard '+'/'/' alphabet, and
 * non-canonical trailing bits are all rejected), the header is pinned to alg=EdDSA / crv=Ed25519 /
 * typ=GMT BEFORE any signature work, and the ver gate fails closed on an unknown format version.
 * What it deliberately skips is the full claim-table validation and failure-reason taxonomy —
 * that lives in the SDKs (starter / Swift / Go); this returns the raw decoded claims for display.
 */

export interface DecodedTokenHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  crv?: string;
  [key: string]: unknown;
}

export interface DecodedTokenPayload {
  ver?: number;
  lid?: string;
  kid?: string;
  prd?: string;
  pol?: string;
  hld?: { n?: string; e?: string };
  iat?: number;
  nbf?: number;
  exp?: number | null;
  ent?: Record<string, unknown>;
  con?: Record<string, unknown>;
  seat?: number;
  [key: string]: unknown;
}

export interface OfflineVerificationResult {
  signatureValid: boolean;
  header: DecodedTokenHeader;
  payload: DecodedTokenPayload;
  expired: boolean;
  notYetValid: boolean;
}

export class TokenFormatError extends Error {}

/** Ed25519 WebCrypto support varies (Chrome/Safari 2024+ generally; older browsers lack it). */
export function browserSupportsEd25519(): boolean {
  return typeof crypto !== 'undefined' && typeof crypto.subtle?.importKey === 'function';
}

/**
 * Accepts base64 OR base64url, padded or not — for the PUBLIC KEY input only, where operators may
 * paste either form. Token segments never go through this; they use the strict decoder below.
 */
function base64AnyToBytes(input: string): Uint8Array {
  const cleaned = input.trim().replace(/\s+/g, '');
  const base64 = cleaned.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * STRICT unpadded base64url for token segments — the wire admits exactly one text form per byte
 * string. Padding, the standard '+'/'/' alphabet, and non-zero unused trailing bits (an alternate
 * spelling of the same bytes) are all malformed, exactly as in the Java/Swift/Go verifiers.
 */
function base64UrlStrictToBytes(segment: string): Uint8Array {
  if (segment.length === 0 || /[^A-Za-z0-9\-_]/.test(segment)) {
    throw new TokenFormatError('malformed token segment (strict unpadded base64url required)');
  }
  const base64 = segment.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new TokenFormatError('malformed token segment (not decodable base64url)');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  // Canonicality: re-encoding must reproduce the exact segment (rejects non-zero trailing bits).
  let reencoded = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const chunk = bytes.subarray(i, i + 3);
    const n = (chunk[0] << 16) | ((chunk[1] ?? 0) << 8) | (chunk[2] ?? 0);
    reencoded += BASE64URL_ALPHABET[(n >> 18) & 63] + BASE64URL_ALPHABET[(n >> 12) & 63];
    if (chunk.length > 1) reencoded += BASE64URL_ALPHABET[(n >> 6) & 63];
    if (chunk.length > 2) reencoded += BASE64URL_ALPHABET[n & 63];
  }
  if (reencoded !== segment) {
    throw new TokenFormatError('malformed token segment (non-canonical base64url spelling)');
  }
  return bytes;
}

function base64UrlStrictToText(segment: string): string {
  return new TextDecoder().decode(base64UrlStrictToBytes(segment));
}

/**
 * Verifies `token` against `publicKeyBase64` entirely in the browser via WebCrypto. Throws
 * TokenFormatError for structurally invalid input; throws for WebCrypto/import failures (caller
 * should treat those as "verification unavailable," see browserSupportsEd25519).
 */
export async function verifyTokenOffline(
  token: string,
  publicKeyBase64: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<OfflineVerificationResult> {
  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    throw new TokenFormatError('token must have exactly 3 non-empty dot-separated segments');
  }
  const [headerSegment, payloadSegment, signatureSegment] = parts;

  let header: DecodedTokenHeader;
  let payload: DecodedTokenPayload;
  try {
    header = JSON.parse(base64UrlStrictToText(headerSegment)) as DecodedTokenHeader;
    payload = JSON.parse(base64UrlStrictToText(payloadSegment)) as DecodedTokenPayload;
  } catch (e) {
    if (e instanceof TokenFormatError) throw e;
    throw new TokenFormatError('malformed token segment (not valid JSON)');
  }

  // Scheme + type pin BEFORE any signature work — same as every real verifier (closes JWT
  // algorithm confusion; a foreign token shape is never treated as a Grantmint license).
  if (
    typeof header.kid !== 'string' ||
    header.alg !== 'EdDSA' ||
    header.crv !== 'Ed25519' ||
    header.typ !== 'GMT'
  ) {
    throw new TokenFormatError('header is not pinned to alg=EdDSA, crv=Ed25519, typ=GMT');
  }
  // Format-version gate: fail closed on a layout this demo does not understand.
  if (payload.ver !== 1) {
    throw new TokenFormatError('unsupported token format version');
  }

  const signingInput = new TextEncoder().encode(`${headerSegment}.${payloadSegment}`);
  const signature = base64UrlStrictToBytes(signatureSegment);
  if (signature.length !== 64) {
    throw new TokenFormatError('signature is not 64 bytes');
  }
  const publicKeyBytes = base64AnyToBytes(publicKeyBase64);

  // TypeScript's lib.dom BufferSource typing is stricter about ArrayBuffer vs ArrayBufferLike than
  // these values actually need to be at runtime (they are always backed by a plain ArrayBuffer,
  // never a SharedArrayBuffer) — cast at the WebCrypto boundary rather than fight the generic.
  const key = await crypto.subtle.importKey(
    'raw',
    publicKeyBytes as BufferSource,
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
  const signatureValid = await crypto.subtle.verify(
    'Ed25519',
    key,
    signature as BufferSource,
    signingInput as BufferSource,
  );

  const expired = typeof payload.exp === 'number' && nowSeconds >= payload.exp;
  const notYetValid = typeof payload.nbf === 'number' && nowSeconds < payload.nbf;

  return { signatureValid, header, payload, expired, notYetValid };
}
