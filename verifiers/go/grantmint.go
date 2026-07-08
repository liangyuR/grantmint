// Package grantmint verifies Grantmint license tokens fully offline against an embedded
// Ed25519 public key — the executable Go counterpart of the verifier documented in
// docs/features/CLIENT_SDK.md, held to the reference implementation byte-for-byte by the
// pinned vector in docs/testing/CROSS_VERIFIER_FIXTURES.md.
//
// Licensed under the Apache License, Version 2.0 (like the Spring Boot starter and the other
// client verifiers — this code is meant to be embedded in downstream, possibly closed-source,
// applications). See docs/security/OPERATOR_AND_LICENSE_NOTES.md.
//
// The wire contract this package enforces (docs/features/LICENSE_TOKEN_FORMAT.md):
//
//   - exactly three non-empty dot-separated segments, each strict unpadded base64url — one
//     text form per byte string, so padding AND non-zero trailing bits are malformed;
//   - header carrying string alg/typ/kid/crv, pinned to alg=EdDSA, crv=Ed25519, typ=GMT
//     before any signature work;
//   - Ed25519 signature over the ASCII bytes of the RECEIVED header.payload (never re-serialized);
//   - strict payload parse: duplicate object keys are malformed, numbers are integers only
//     within int64; ver must equal 1; lid/kid/prd/pol non-empty strings, hld an object with
//     non-empty string n/e, iat an integer, and ent an object are all required; con (object)
//     and seat (an integer within int32, matching the reference's int parse) are optional but
//     never wrong-typed; exp is a required key whose value may be null (perpetual);
//   - optional product binding ([VerifyForProduct]): a caller-supplied expected product must
//     equal the authenticated prd claim, checked between the format-version gate and the
//     temporal window exactly like the reference — an expired sibling-product token is
//     ErrWrongProduct, never ErrExpired in one verifier and ErrWrongProduct in another;
//   - now >= exp is expired (exp exclusive); now < nbf is not yet valid (nbf optional).
package grantmint

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
)

var (
	ErrMalformed = errors.New("grantmint: malformed token")
	// ErrAlgNotAllowed is the Java reference's ALG_NOT_ALLOWED: the header does not pin the one
	// allowed signature scheme (alg=EdDSA over crv=Ed25519) — an algorithm- or curve-confusion
	// attempt, rejected before any signature work.
	ErrAlgNotAllowed = errors.New("grantmint: signature scheme not allowed")
	// ErrWrongType is the Java reference's WRONG_TYPE: the header typ is not GMT — a correctly
	// structured token that is not a Grantmint license (e.g. a generic JWT), rejected before any
	// signature work.
	ErrWrongType    = errors.New("grantmint: not a grantmint license token")
	ErrBadSignature = errors.New("grantmint: signature mismatch")
	ErrExpired      = errors.New("grantmint: token expired")
	ErrNotYetValid  = errors.New("grantmint: token not yet valid")
	// ErrUnsupportedVersion is the Java reference's UNSUPPORTED_VERSION: the signature is sound
	// but the claims declare a format version this verifier does not know — an authentic token
	// from a future issuer, rejected fail-closed with its own reason (telemetry can tell "update
	// the verifier" apart from a corrupt token). A wrong-typed or out-of-int32-range ver stays
	// ErrMalformed, exactly like the reference.
	ErrUnsupportedVersion = errors.New("grantmint: unsupported token format version")
	// ErrWrongProduct is the Java reference's WRONG_PRODUCT: an authentic token whose prd claim
	// does not match the product the caller bound via VerifyForProduct — a sibling product's
	// license signed by the same key pair, rejected after the format-version gate and before the
	// temporal window.
	ErrWrongProduct = errors.New("grantmint: token bound to a different product")
)

// b64 rejects the standard alphabet and '=' padding by construction (RawURLEncoding) and
// non-zero trailing bits via Strict() — exactly one text form decodes to any byte string.
var b64 = base64.RawURLEncoding.Strict()

// Verify checks a Grantmint token offline against the raw 32-byte Ed25519 public key (hex),
// as of now (Unix epoch seconds, UTC), without binding it to a product. It returns the
// authenticated payload claims: integers as int64, objects as map[string]any, arrays as []any,
// plus string/bool/nil.
func Verify(token, publicKeyHex string, now int64) (map[string]any, error) {
	return VerifyForProduct(token, publicKeyHex, now, "")
}

// VerifyForProduct is [Verify] bound to an expected product: when expectedProduct is non-empty,
// the authenticated prd claim must equal it or the token is rejected with ErrWrongProduct — the
// Java reference's WRONG_PRODUCT, checked between the format-version gate and the temporal
// window. This closes the cross-product acceptance gap in a deployment where one Ed25519 key
// pair signs tokens for several products: a sibling product's authentic token would otherwise
// verify here. Pass "" to skip the binding (the single-product case, where the embedded public
// key already scopes trust).
func VerifyForProduct(token, publicKeyHex string, now int64, expectedProduct string) (map[string]any, error) {
	pub, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, ErrMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, ErrMalformed
	}
	headerBytes, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	if _, err := b64.DecodeString(parts[1]); err != nil {
		return nil, ErrMalformed
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}

	// Pin the scheme BEFORE touching the signature (closes JWT algorithm confusion). Like the
	// Java reference, the header must carry all four fields as strings — a kid-less header is
	// malformed — and then alg/crv/typ must hold exactly the pinned values, each failure keeping
	// the reference's distinct reason: ALG_NOT_ALLOWED, then WRONG_TYPE, in that order.
	header, err := parseStrictObject(headerBytes)
	if err != nil {
		return nil, ErrMalformed
	}
	for _, field := range []string{"alg", "typ", "kid", "crv"} {
		if _, ok := header[field].(string); !ok {
			return nil, ErrMalformed
		}
	}
	if header["alg"] != "EdDSA" || header["crv"] != "Ed25519" {
		return nil, ErrAlgNotAllowed
	}
	if header["typ"] != "GMT" {
		return nil, ErrWrongType
	}

	// Signature over the RECEIVED segments joined by a literal dot — never a re-serialization.
	signingInput := []byte(parts[0] + "." + parts[1])
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), signingInput, sig) {
		return nil, ErrBadSignature
	}

	// Claims are trustworthy only past this point.
	payloadBytes, _ := b64.DecodeString(parts[1]) // already validated above
	claims, err := parseStrictObject(payloadBytes)
	if err != nil {
		return nil, ErrMalformed
	}
	// The claim table (LICENSE_TOKEN_FORMAT.md) marks lid/kid/prd/pol/hld/iat required — with
	// non-empty strings — and ent a required object. The Java, Swift, and starter verifiers all
	// reject a validly-signed token missing any of them as malformed; this verifier must agree
	// on every byte (CROSS_VERIFIER_FIXTURES.md).
	for _, key := range []string{"lid", "kid", "prd", "pol"} {
		s, ok := claims[key].(string)
		if !ok || s == "" {
			return nil, ErrMalformed
		}
	}
	hld, ok := claims["hld"].(map[string]any)
	if !ok {
		return nil, ErrMalformed
	}
	for _, key := range []string{"n", "e"} {
		s, ok := hld[key].(string)
		if !ok || s == "" {
			return nil, ErrMalformed
		}
	}
	if _, ok := claims["iat"].(int64); !ok {
		return nil, ErrMalformed
	}
	ent, ok := claims["ent"].(map[string]any)
	if !ok {
		return nil, ErrMalformed
	}
	// The reference's EntitlementSet.decode admits exactly flag | limit | string values under
	// canonical snake_case keys (^[a-z][a-z0-9_]{0,62}$ — the grammar the server enforces at
	// entitlement creation); anything else in a signed ent is malformed there and so must be
	// here. Rejecting non-canonical keys (rather than normalizing) keeps two JSON-distinct keys
	// like "MAX_DEVICES"/"max_devices" from collapsing last-wins in one SDK while staying
	// distinct in another.
	for key, value := range ent {
		if !isCanonicalEntitlementKey(key) {
			return nil, ErrMalformed
		}
		switch value.(type) {
		case bool, int64, string:
		default:
			return nil, ErrMalformed
		}
	}
	// Optional claims may be absent (or JSON null, treated as absent) but never wrong-typed:
	// con must be an object, seat an integer — silently ignoring a mistyped claim would let
	// this verifier accept bytes every other implementation rejects.
	if conRaw, present := claims["con"]; present && conRaw != nil {
		if _, ok := conRaw.(map[string]any); !ok {
			return nil, ErrMalformed
		}
	}
	if seatRaw, present := claims["seat"]; present && seatRaw != nil {
		// seat is a plain int in the spec's claim table, and the reference parses it with
		// Math.toIntExact — an int64 beyond the 32-bit range is malformed there, so it must
		// be malformed here too, never silently widened.
		seat, ok := seatRaw.(int64)
		if !ok || seat < math.MinInt32 || seat > math.MaxInt32 {
			return nil, ErrMalformed
		}
	}
	// exp is a REQUIRED key whose value may be null (perpetual), and a present exp/nbf must be
	// an integer. Both are claim-TABLE checks, so they run before the format-version gate,
	// exactly where the reference's payload parse rejects them: a ver=2 token missing exp is
	// MALFORMED there, never UNSUPPORTED_VERSION. Absence of exp is malformed — never silently
	// perpetual.
	expRaw, present := claims["exp"]
	if !present {
		return nil, ErrMalformed
	}
	var exp *int64
	if expRaw != nil {
		value, isInt := expRaw.(int64)
		if !isInt {
			return nil, ErrMalformed
		}
		exp = &value
	}
	var nbf *int64
	if nbfRaw, hasNbf := claims["nbf"]; hasNbf && nbfRaw != nil {
		value, isInt := nbfRaw.(int64)
		if !isInt {
			return nil, ErrMalformed
		}
		nbf = &value
	}
	ver, ok := claims["ver"].(int64)
	if !ok || ver < math.MinInt32 || ver > math.MaxInt32 {
		return nil, ErrMalformed // wrong-typed or out-of-int32-range, like any other claim
	}
	if ver != 1 {
		return nil, ErrUnsupportedVersion // authentic but from a future format — fail closed
	}
	// Product binding — an authentic token for a sibling product (same signing key pair) must
	// not pass another product's gate. Sits between the version gate and the temporal window
	// like the reference, so an expired sibling-product token reports ErrWrongProduct here and
	// WRONG_PRODUCT there — the same verdict for the same bytes.
	if expectedProduct != "" && claims["prd"] != expectedProduct {
		return nil, ErrWrongProduct
	}
	if nbf != nil && now < *nbf {
		return nil, ErrNotYetValid
	}
	if exp != nil && now >= *exp { // exp is exclusive
		return nil, ErrExpired
	}
	return claims, nil
}

// isCanonicalEntitlementKey is the reference's EntitlementKey.isCanonical:
// ^[a-z][a-z0-9_]{0,62}$. A pure ASCII character-class check — byte-deterministic across the
// Java, Swift, Go, and TS verifiers, with no Unicode case-folding parity risk.
func isCanonicalEntitlementKey(key string) bool {
	if len(key) < 1 || len(key) > 63 {
		return false
	}
	if key[0] < 'a' || key[0] > 'z' {
		return false
	}
	for i := 1; i < len(key); i++ {
		c := key[i]
		lower := c >= 'a' && c <= 'z'
		digit := c >= '0' && c <= '9'
		if !lower && !digit && c != '_' {
			return false
		}
	}
	return true
}

// parseStrictObject decodes a JSON object with the wire's strictness: duplicate member names
// are malformed (never first- or last-wins), numbers are integers only within int64 (the
// canonical writer never emits anything else), and trailing content is malformed.
func parseStrictObject(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, ErrMalformed
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, ErrMalformed
	}
	return obj, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, ErrMalformed
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, ErrMalformed
				}
				key, isString := keyTok.(string)
				if !isString {
					return nil, ErrMalformed
				}
				if _, dup := obj[key]; dup {
					return nil, ErrMalformed // duplicate member names are undefined JSON — pinned as an error
				}
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return nil, ErrMalformed
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, ErrMalformed
			}
			return arr, nil
		}
		return nil, ErrMalformed
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return nil, ErrMalformed // integers only — canonical JSON never emits a fraction/exponent
		}
		n, err := t.Int64()
		if err != nil {
			return nil, ErrMalformed // out of the signed 64-bit cross-language contract
		}
		return n, nil
	case string:
		return t, nil
	case bool:
		return t, nil
	case nil:
		return nil, nil
	}
	return nil, ErrMalformed
}
