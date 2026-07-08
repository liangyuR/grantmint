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
 * client SDK — but it now enforces the SAME strict wire contract as the shipped SDK verifiers
 * (grantmint-spring-boot-starter's StrictJson + OfflineTokenVerifier, and the Swift/Go verifiers):
 * token segments are STRICT unpadded base64url; the header is pinned to alg=EdDSA / crv=Ed25519 /
 * typ=GMT BEFORE any signature work; the payload is read with a hand-rolled strict JSON parser
 * (duplicate object keys rejected, numbers are integers only within signed 64-bit — no fractions,
 * exponents, leading zeros/plus, or out-of-int64 magnitudes); and — only once the signature is
 * confirmed authentic — the FULL claim table is enforced exactly like
 * OfflineTokenVerifier.checkClaims (required non-empty strings, hld shape, ent value types, the
 * seat int32 range, the ver==1 gate, and the exp/nbf temporal window). A validly-signed-but-
 * malformed payload is rejected as malformed here too, never silently read as VALID — see
 * docs/testing/CROSS_VERIFIER_FIXTURES.md.
 *
 * Decision order (mirrors OfflineTokenVerifier.verifyAt/checkClaims):
 *   1. token must be 3 non-empty dot-separated segments
 *   2. each segment strict-unpadded-base64url-decodable
 *   3. header parses as strict JSON; alg/typ/kid/crv present as strings; alg==EdDSA && crv==Ed25519;
 *      typ==GMT — all BEFORE any signature work
 *   4. Ed25519 signature verified over the received header+"."+payload segment bytes
 *   5. only if the signature is valid: payload parsed as strict JSON and the full claim table is
 *      enforced (exp present, nbf/iat/kid/lid/prd/pol/hld/ent/seat/con/ver — see checkClaims below)
 *   6. optional product binding: a caller-supplied expectedProduct must equal the authenticated
 *      prd claim ('wrong_product'), checked between the format-version gate and the temporal
 *      window exactly like the reference — an expired sibling-product token is wrong_product,
 *      never expired in one verifier and wrong_product in another
 *   7. temporal window: now < nbf -> notYetValid; exp != null && now >= exp -> expired (exclusive)
 *
 * What's illustrative-only, not the SDK: this file is a from-scratch WebCrypto reimplementation for
 * the dashboard demo page, not a distributed client library — use the starter/CLI/SDKs for real
 * integrations.
 */

export interface DecodedTokenHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  crv?: string;
  [key: string]: unknown;
}

/**
 * An int64 claim as it appears in the DISPLAY payload: a plain number, or its exact decimal
 * string once the value exceeds Number.MAX_SAFE_INTEGER (2^53) — the wire contract is full int64
 * (Java/Go/Swift read 64-bit longs), so an authentic far-future `exp` or extreme entitlement
 * limit is stringified for lossless display rather than silently rounded through a double
 * (GRANTMINT-169: the declared types must admit that, not hide it behind a cast).
 */
export type DisplayInt64 = number | string;

/**
 * The decoded claims as shown by the demo page — display data, not a verification API. On the
 * happy path every field below is exactly what the claim gate verified; when `signatureValid` is
 * false the payload is an UNVERIFIED best-effort decode and no field can be trusted to match its
 * declared type beyond JSON's own shapes.
 */
export interface DecodedTokenPayload {
  ver?: number;
  lid?: string;
  kid?: string;
  prd?: string;
  pol?: string;
  hld?: { n?: string; e?: string };
  iat?: DisplayInt64;
  nbf?: DisplayInt64;
  exp?: DisplayInt64 | null;
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

/**
 * Why the token was refused — the slice of the Java reference's FailureReason taxonomy a browser
 * demo can distinguish (2026-07-05 audit, GRANTMINT-148: the reject verdict always matched the
 * real verifiers, but `unsupported_version` used to collapse into `malformed` here while the Java
 * verifiers report it distinctly — telemetry could not tell "update the verifier" from "corrupt
 * token"; GRANTMINT-153 added `wrong_product` alongside the new expectedProduct binding).
 */
export type TokenFailureReason =
  | 'malformed'
  | 'alg_not_allowed'
  | 'wrong_type'
  | 'unsupported_version'
  | 'wrong_product';

export class TokenFormatError extends Error {
  readonly reason: TokenFailureReason;

  constructor(message: string, reason: TokenFailureReason = 'malformed') {
    super(message);
    this.reason = reason;
  }
}

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
    const n = ((chunk[0] ?? 0) << 16) | ((chunk[1] ?? 0) << 8) | (chunk[2] ?? 0);
    reencoded += BASE64URL_ALPHABET.charAt((n >> 18) & 63) + BASE64URL_ALPHABET.charAt((n >> 12) & 63);
    if (chunk.length > 1) reencoded += BASE64URL_ALPHABET.charAt((n >> 6) & 63);
    if (chunk.length > 2) reencoded += BASE64URL_ALPHABET.charAt(n & 63);
  }
  if (reencoded !== segment) {
    throw new TokenFormatError('malformed token segment (non-canonical base64url spelling)');
  }
  return bytes;
}

// ─── Strict JSON — a browser port of grantmint-spring-boot-starter's StrictJson.java ──────────────
//
// Deliberately less forgiving than JSON.parse/`JSON.parse`, because every offline verifier must
// read the SAME signed bytes identically or refuse (docs/testing/CROSS_VERIFIER_FIXTURES.md):
// duplicate object keys are an error (never first/last-wins), numbers are integers only — no
// fraction, no exponent, no leading zeros/plus — and must fit a signed 64-bit range. JS numbers
// lose integer precision past 2^53, so integer literals within that range decode to `number`;
// larger-but-still-int64 literals decode to `bigint`. The wire contract permits full int64 for
// epoch claims and entitlement limits (the Java/Go/Swift verifiers read them as 64-bit longs), so
// the epoch and entitlement gates below accept `bigint` too — only inherently-32-bit claims
// (`seat`, `ver`) reject it, exactly like the reference's Math.toIntExact.

type JsonValue = string | number | bigint | boolean | null | JsonValue[] | { [key: string]: JsonValue };

const INT64_MIN = -9223372036854775808n;
const INT64_MAX = 9223372036854775807n;
const SAFE_MIN = BigInt(Number.MIN_SAFE_INTEGER);
const SAFE_MAX = BigInt(Number.MAX_SAFE_INTEGER);

function isDigit(c: string | undefined): boolean {
  return c !== undefined && c >= '0' && c <= '9';
}

class StrictJsonParser {
  private pos = 0;

  constructor(private readonly text: string) {}

  /** Parse a complete JSON document that must be a single object (mirrors StrictJson.parseObject). */
  static parseObject(text: string): Record<string, JsonValue> {
    const parser = new StrictJsonParser(text);
    parser.skipWhitespace();
    const value = parser.parseValue();
    parser.skipWhitespace();
    if (parser.pos !== text.length) {
      throw new TokenFormatError('trailing content after JSON value');
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new TokenFormatError('expected a JSON object');
    }
    return value;
  }

  private parseValue(): JsonValue {
    if (this.pos >= this.text.length) {
      throw new TokenFormatError('unexpected end of JSON');
    }
    const c = this.text[this.pos];
    switch (c) {
      case '{':
        return this.parseObjectValue();
      case '[':
        return this.parseArray();
      case '"':
        return this.parseString();
      case 't':
        return this.parseLiteral('true', true);
      case 'f':
        return this.parseLiteral('false', false);
      case 'n':
        return this.parseLiteral('null', null);
      default:
        return this.parseNumber();
    }
  }

  private parseObjectValue(): Record<string, JsonValue> {
    this.expect('{');
    // Object.create(null): no prototype chain, so `key in object` below is a safe, exact duplicate
    // check even for adversarial keys like "__proto__" or "constructor".
    const object: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    this.skipWhitespace();
    if (this.peek() === '}') {
      this.pos += 1;
      return object;
    }
    for (;;) {
      this.skipWhitespace();
      const key = this.parseString();
      if (key in object) {
        // Undefined in JSON, divergent across parsers — pinned as an error so every language reads
        // identical bytes identically.
        throw new TokenFormatError(`duplicate object key: ${key}`);
      }
      this.skipWhitespace();
      this.expect(':');
      this.skipWhitespace();
      object[key] = this.parseValue();
      this.skipWhitespace();
      const next = this.next();
      if (next === '}') {
        return object;
      }
      if (next !== ',') {
        throw new TokenFormatError("expected ',' or '}' in object");
      }
    }
  }

  private parseArray(): JsonValue[] {
    this.expect('[');
    const array: JsonValue[] = [];
    this.skipWhitespace();
    if (this.peek() === ']') {
      this.pos += 1;
      return array;
    }
    for (;;) {
      this.skipWhitespace();
      array.push(this.parseValue());
      this.skipWhitespace();
      const next = this.next();
      if (next === ']') {
        return array;
      }
      if (next !== ',') {
        throw new TokenFormatError("expected ',' or ']' in array");
      }
    }
  }

  private parseString(): string {
    this.expect('"');
    let result = '';
    for (;;) {
      if (this.pos >= this.text.length) {
        throw new TokenFormatError('unterminated string');
      }
      const c = this.text[this.pos];
      this.pos += 1;
      if (c === undefined) {
        throw new TokenFormatError('unterminated string');
      }
      if (c === '"') {
        return result;
      }
      if (c.charCodeAt(0) < 0x20) {
        throw new TokenFormatError('unescaped control character in string');
      }
      if (c !== '\\') {
        result += c;
        continue;
      }
      if (this.pos >= this.text.length) {
        throw new TokenFormatError('unterminated escape');
      }
      const escape = this.text[this.pos];
      this.pos += 1;
      switch (escape) {
        case '"':
          result += '"';
          break;
        case '\\':
          result += '\\';
          break;
        case '/':
          result += '/';
          break;
        case 'b':
          result += '\b';
          break;
        case 'f':
          result += '\f';
          break;
        case 'n':
          result += '\n';
          break;
        case 'r':
          result += '\r';
          break;
        case 't':
          result += '\t';
          break;
        case 'u': {
          if (this.pos + 4 > this.text.length) {
            throw new TokenFormatError('truncated unicode escape');
          }
          const hex = this.text.slice(this.pos, this.pos + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
            throw new TokenFormatError('invalid unicode escape');
          }
          result += String.fromCharCode(parseInt(hex, 16));
          this.pos += 4;
          break;
        }
        default:
          throw new TokenFormatError(`invalid escape: \\${escape ?? ''}`);
      }
    }
  }

  private parseNumber(): number | bigint {
    const start = this.pos;
    if (this.peek() === '-') {
      this.pos += 1;
    }
    if (this.pos >= this.text.length || !isDigit(this.text[this.pos])) {
      throw new TokenFormatError('invalid number');
    }
    // Integer-only lexer with the canonical no-leading-zero rule ("0" alone is fine).
    if (this.text[this.pos] === '0' && isDigit(this.text[this.pos + 1])) {
      throw new TokenFormatError('leading zero in number');
    }
    while (this.pos < this.text.length && isDigit(this.text[this.pos])) {
      this.pos += 1;
    }
    const trailing = this.text[this.pos];
    if (trailing === '.' || trailing === 'e' || trailing === 'E') {
      throw new TokenFormatError('non-integer number in canonical JSON');
    }
    const raw = this.text.slice(start, this.pos);
    let value: bigint;
    try {
      value = BigInt(raw);
    } catch {
      throw new TokenFormatError('invalid integer literal');
    }
    if (value < INT64_MIN || value > INT64_MAX) {
      throw new TokenFormatError('integer out of 64-bit range');
    }
    if (value >= SAFE_MIN && value <= SAFE_MAX) {
      return Number(value);
    }
    return value;
  }

  private parseLiteral<T extends JsonValue>(literal: string, value: T): T {
    if (this.text.slice(this.pos, this.pos + literal.length) !== literal) {
      throw new TokenFormatError('invalid JSON literal');
    }
    this.pos += literal.length;
    return value;
  }

  private skipWhitespace(): void {
    while (this.pos < this.text.length) {
      const c = this.text[this.pos];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
        this.pos += 1;
      } else {
        return;
      }
    }
  }

  private peek(): string {
    const c = this.text[this.pos];
    if (c === undefined) {
      throw new TokenFormatError('unexpected end of JSON');
    }
    return c;
  }

  private next(): string {
    const c = this.peek();
    this.pos += 1;
    return c;
  }

  private expect(expected: string): void {
    if (this.next() !== expected) {
      throw new TokenFormatError(`expected '${expected}'`);
    }
  }
}

function parseStrictJsonObject(text: string): Record<string, JsonValue> {
  return StrictJsonParser.parseObject(text);
}

// ─── Header pinning ────────────────────────────────────────────────────────────────────────────

function pinHeader(header: Record<string, JsonValue>): void {
  for (const field of ['alg', 'typ', 'kid', 'crv'] as const) {
    if (typeof header[field] !== 'string') {
      throw new TokenFormatError(`header field '${field}' must be a string`);
    }
  }
  if (header.alg !== 'EdDSA' || header.crv !== 'Ed25519') {
    throw new TokenFormatError('header is not pinned to alg=EdDSA, crv=Ed25519', 'alg_not_allowed');
  }
  if (header.typ !== 'GMT') {
    throw new TokenFormatError('header typ is not GMT', 'wrong_type');
  }
}

// ─── Claim table — mirrors OfflineTokenVerifier.checkClaims decision-for-decision ─────────────────

function requiredString(claims: Record<string, JsonValue>, key: string): string {
  const value = claims[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new TokenFormatError(`missing required claim: ${key}`);
  }
  return value;
}

function optionalObject(claims: Record<string, JsonValue>, key: string): Record<string, JsonValue> | undefined {
  const value = claims[key];
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TokenFormatError(`${key} must be a JSON object`);
  }
  return value;
}

function requiredObject(claims: Record<string, JsonValue>, key: string): Record<string, JsonValue> {
  const value = optionalObject(claims, key);
  if (value === undefined) {
    throw new TokenFormatError(`missing required claim: ${key}`);
  }
  return value;
}

/**
 * The reference's `EntitlementKey.isCanonical`: `^[a-z][a-z0-9_]{0,62}$`. A pure ASCII
 * character-class check — byte-deterministic across the Java, Swift, Go, and TS verifiers, with
 * no Unicode case-folding parity risk.
 */
function isCanonicalEntitlementKey(key: string): boolean {
  return /^[a-z][a-z0-9_]{0,62}$/.test(key);
}

/** `now < epoch` across the number/bigint split the strict parser produces for int64 claims. */
function nowBeforeEpoch(nowSeconds: number, epoch: number | bigint): boolean {
  return typeof epoch === 'bigint' ? BigInt(Math.trunc(nowSeconds)) < epoch : nowSeconds < epoch;
}

function requiredEpoch(claims: Record<string, JsonValue>, key: string): number | bigint {
  const value = claims[key];
  // int64 on the wire: within 2^53 the strict parser yields `number`, beyond it `bigint` — both
  // are authentic integer epochs and the reference verifiers accept the full 64-bit range.
  if (typeof value !== 'number' && typeof value !== 'bigint') {
    throw new TokenFormatError(`missing required integer claim: ${key}`);
  }
  return value;
}

function optionalEpoch(claims: Record<string, JsonValue>, key: string): number | bigint | undefined {
  const value = claims[key];
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'number' && typeof value !== 'bigint') {
    throw new TokenFormatError(`${key} must be an integer epoch second`);
  }
  return value;
}

/**
 * The spec types `seat` as a plain 32-bit int (not an epoch second) and the reference parses it
 * with `Math.toIntExact` — a value outside the 32-bit range is malformed here exactly as it is
 * there, never silently widened. Same rationale as the `ver` gate below.
 */
function optionalInt32(claims: Record<string, JsonValue>, key: string): number | undefined {
  const value = optionalEpoch(claims, key);
  if (value === undefined) {
    return undefined;
  }
  // A bigint is by construction outside 2^53, so it can never fit an int32 — same rejection the
  // reference's Math.toIntExact produces for an int64 beyond the 32-bit range.
  if (typeof value === 'bigint' || value < -2147483648 || value > 2147483647) {
    throw new TokenFormatError(`${key} must fit a 32-bit integer`);
  }
  return value;
}

interface ClaimCheckResult {
  expired: boolean;
  notYetValid: boolean;
}

function checkClaims(
  claims: Record<string, JsonValue>,
  nowSeconds: number,
  expectedProduct?: string,
): ClaimCheckResult {
  // exp is REQUIRED on the wire; its value may be null (perpetual). Absence is malformed — never
  // silently perpetual (CROSS_VERIFIER_FIXTURES.md, perpetual licenses note).
  if (!('exp' in claims)) {
    throw new TokenFormatError('exp claim is required (null means perpetual, absent is invalid)');
  }
  const exp = optionalEpoch(claims, 'exp');
  const nbf = optionalEpoch(claims, 'nbf');
  // The spec's claim table marks lid/kid/prd/pol/hld/iat required non-empty and ent a required
  // object; mirror the reference verifier exactly: absence, a wrong type, or an empty required
  // string is MALFORMED, never a silently-defaulted field — and every structural check runs before
  // the version gate and the temporal window so both implementations report the same verdict for
  // the same bytes.
  requiredEpoch(claims, 'iat');
  requiredString(claims, 'kid');
  requiredString(claims, 'lid');
  requiredString(claims, 'prd');
  requiredString(claims, 'pol');
  const holder = requiredObject(claims, 'hld');
  requiredString(holder, 'n');
  requiredString(holder, 'e');
  const entitlements = requiredObject(claims, 'ent');
  // Exactly flag | limit | string values under canonical snake_case keys
  // (^[a-z][a-z0-9_]{0,62}$ — the grammar the server enforces at entitlement creation); anything
  // else in a signed ent is malformed in the reference and so must be here. Rejecting
  // non-canonical keys (rather than normalizing) keeps two JSON-distinct keys like
  // "MAX_DEVICES"/"max_devices" from collapsing last-wins in one SDK while staying distinct in
  // another. Limit values are int64 on the wire, so `bigint` (beyond 2^53) is accepted like the
  // reference's 64-bit long.
  for (const [key, value] of Object.entries(entitlements)) {
    if (!isCanonicalEntitlementKey(key)) {
      throw new TokenFormatError('entitlement keys must be canonical snake_case');
    }
    if (
      typeof value !== 'boolean' &&
      typeof value !== 'number' &&
      typeof value !== 'bigint' &&
      typeof value !== 'string'
    ) {
      throw new TokenFormatError('entitlement values must be a boolean flag, integer limit, or string');
    }
  }
  optionalInt32(claims, 'seat');
  optionalObject(claims, 'con');

  // Format-version gate — the structure is sound, but refuse to interpret a layout this verifier
  // does not understand. A non-integer (or bigint/boolean) ver is malformed like any other claim; a
  // well-typed unknown version carries the reference's distinct UNSUPPORTED_VERSION reason, same
  // granularity as the Java verifiers.
  const version = claims.ver;
  if (typeof version !== 'number' || version < -2147483648 || version > 2147483647) {
    throw new TokenFormatError('ver must be an integer format version');
  }
  if (version !== 1) {
    throw new TokenFormatError(`unsupported token version ${version}`, 'unsupported_version');
  }

  // Product binding — an authentic token for a sibling product (same signing key pair) must not
  // pass another product's gate. Sits between the version gate and the temporal window like the
  // reference, so an expired sibling-product token reports wrong_product here and WRONG_PRODUCT
  // there — the same verdict for the same bytes.
  if (expectedProduct !== undefined && claims.prd !== expectedProduct) {
    throw new TokenFormatError(
      `token is for product '${String(claims.prd)}', not '${expectedProduct}'`,
      'wrong_product',
    );
  }

  return {
    notYetValid: nbf !== undefined && nowBeforeEpoch(nowSeconds, nbf),
    expired: exp !== undefined && !nowBeforeEpoch(nowSeconds, exp),
  };
}

// ─── Display conversion — never let a stray bigint reach JSON.stringify in the demo page ─────────

function toDisplayValue(value: JsonValue): unknown {
  if (typeof value === 'bigint') {
    // Reachable by any int64 claim above 2^53 — including an authentic far-future exp/nbf/iat or
    // an extreme entitlement limit (the epoch gates accept bigint by design). Stringify the exact
    // decimal for lossless display rather than crash `JSON.stringify`; DisplayInt64 declares this
    // number-or-string shape honestly (GRANTMINT-169).
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map(toDisplayValue);
  }
  if (value !== null && typeof value === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      result[key] = toDisplayValue(nested);
    }
    return result;
  }
  return value;
}

function toDisplayHeader(header: Record<string, JsonValue>): DecodedTokenHeader {
  return toDisplayValue(header) as DecodedTokenHeader;
}

function toDisplayPayload(payload: Record<string, JsonValue>): DecodedTokenPayload {
  return toDisplayValue(payload) as DecodedTokenPayload;
}

/**
 * Verifies `token` against `publicKeyBase64` entirely in the browser via WebCrypto. Throws
 * TokenFormatError for structurally invalid input — including a validly-signed-but-malformed
 * payload, which is exactly the audit finding this rewrite fixes (a lenient demo verifier must
 * never display "VALID" for bytes every real verifier rejects). Throws for WebCrypto/import
 * failures too (caller should treat those as "verification unavailable," see
 * browserSupportsEd25519).
 *
 * When `expectedProduct` is provided, the authenticated `prd` claim must equal it or the token is
 * rejected with reason 'wrong_product' — the Java reference's WRONG_PRODUCT, checked between the
 * format-version gate and the temporal window. Omit it to skip the binding (the single-product
 * case, where the embedded public key already scopes trust).
 */
export async function verifyTokenOffline(
  token: string,
  publicKeyBase64: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
  expectedProduct?: string,
): Promise<OfflineVerificationResult> {
  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    throw new TokenFormatError('token must have exactly 3 non-empty dot-separated segments');
  }
  const [headerSegment, payloadSegment, signatureSegment] = parts as [string, string, string];

  // Decodability of every segment is part of well-formedness, checked up front — same as the
  // reference verifier's Base64Url.decodeStrict calls, in the same order (header, payload,
  // signature) before any JSON parsing or signature work.
  const headerBytes = base64UrlStrictToBytes(headerSegment);
  const payloadBytes = base64UrlStrictToBytes(payloadSegment);
  const signature = base64UrlStrictToBytes(signatureSegment);

  let header: Record<string, JsonValue>;
  try {
    header = parseStrictJsonObject(new TextDecoder().decode(headerBytes));
  } catch (e) {
    if (e instanceof TokenFormatError) throw e;
    throw new TokenFormatError('header is not strict JSON');
  }
  // Scheme + type pin BEFORE any signature work — same as every real verifier (closes JWT
  // algorithm confusion; a foreign token shape is never treated as a Grantmint license).
  pinHeader(header);

  const signingInput = new TextEncoder().encode(`${headerSegment}.${payloadSegment}`);
  let signatureValid = false;
  if (signature.length === 64) {
    const publicKeyBytes = base64AnyToBytes(publicKeyBase64);
    // TypeScript's lib.dom BufferSource typing is stricter about ArrayBuffer vs ArrayBufferLike
    // than these values actually need to be at runtime (always backed by a plain ArrayBuffer,
    // never a SharedArrayBuffer) — cast at the WebCrypto boundary rather than fight the generic.
    const key = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes as BufferSource,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    signatureValid = await crypto.subtle.verify(
      'Ed25519',
      key,
      signature as BufferSource,
      signingInput as BufferSource,
    );
  }

  if (!signatureValid) {
    // Claims are untrustworthy here — never run the strict claim-table gate against bytes that
    // did not verify. Still decode best-effort (loose JSON.parse, never throwing) purely so the
    // demo page has something to show alongside "signature invalid"; a decode failure just means
    // an empty claims table is displayed, not a crash.
    let displayPayload: DecodedTokenPayload = {};
    try {
      displayPayload = JSON.parse(new TextDecoder().decode(payloadBytes)) as DecodedTokenPayload;
    } catch {
      // leave displayPayload as {}
    }
    return {
      signatureValid: false,
      header: toDisplayHeader(header),
      payload: displayPayload,
      expired: false,
      notYetValid: false,
    };
  }

  // Claims are trusted only past this point — the signature has spoken. Parse strictly and run the
  // full claim table; a malformed payload throws TokenFormatError rather than reading as VALID.
  let payload: Record<string, JsonValue>;
  try {
    payload = parseStrictJsonObject(new TextDecoder().decode(payloadBytes));
  } catch (e) {
    if (e instanceof TokenFormatError) throw e;
    throw new TokenFormatError('payload is not strict JSON');
  }
  const { expired, notYetValid } = checkClaims(payload, nowSeconds, expectedProduct);

  return {
    signatureValid: true,
    header: toDisplayHeader(header),
    payload: toDisplayPayload(payload),
    expired,
    notYetValid,
  };
}
