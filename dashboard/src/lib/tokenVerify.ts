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
 * client SDK — it does not implement the full ordered failure-reason pipeline (alg/crv/typ pin,
 * ver gate, product binding, nbf/exp) that the real verifiers use; it does the signature check
 * plus a best-effort expiry read, which is enough to make the offline story visible.
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

/** Accepts base64 OR base64url, padded or not — operators may paste either form. */
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

function base64UrlDecodeToText(segment: string): string {
  if (segment.includes('=')) {
    throw new TokenFormatError('malformed token segment (padded base64url is rejected on the wire)');
  }
  return new TextDecoder().decode(base64AnyToBytes(segment));
}

/**
 * Verifies `token` against `publicKeyBase64` entirely in the browser via WebCrypto. Throws
 * TokenFormatError for structurally invalid input; throws for WebCrypto/import failures (caller
 * should treat those as "verification unavailable," see browserSupportsEd25519).
 */
export async function verifyTokenOffline(
  token: string,
  publicKeyBase64: string,
): Promise<OfflineVerificationResult> {
  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    throw new TokenFormatError('token must have exactly 3 non-empty dot-separated segments');
  }
  const [headerSegment, payloadSegment, signatureSegment] = parts;

  const header = JSON.parse(base64UrlDecodeToText(headerSegment)) as DecodedTokenHeader;
  const payload = JSON.parse(base64UrlDecodeToText(payloadSegment)) as DecodedTokenPayload;

  const signingInput = new TextEncoder().encode(`${headerSegment}.${payloadSegment}`);
  const signature = base64AnyToBytes(signatureSegment);
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

  const nowSeconds = Math.floor(Date.now() / 1000);
  const expired = typeof payload.exp === 'number' && nowSeconds >= payload.exp;
  const notYetValid = typeof payload.nbf === 'number' && nowSeconds < payload.nbf;

  return { signatureValid, header, payload, expired, notYetValid };
}
