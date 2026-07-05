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
	ErrMalformed    = errors.New("grantmint: malformed token")
	ErrBadSignature = errors.New("grantmint: signature mismatch")
	ErrExpired      = errors.New("grantmint: token expired")
	ErrNotYetValid  = errors.New("grantmint: token not yet valid")
)

// b64 rejects the standard alphabet and '=' padding by construction (RawURLEncoding) and
// non-zero trailing bits via Strict() — exactly one text form decodes to any byte string.
var b64 = base64.RawURLEncoding.Strict()

// Verify checks a Grantmint token offline against the raw 32-byte Ed25519 public key (hex),
// as of now (Unix epoch seconds, UTC). It returns the authenticated payload claims: integers
// as int64, objects as map[string]any, arrays as []any, plus string/bool/nil.
func Verify(token, publicKeyHex string, now int64) (map[string]any, error) {
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
	// malformed — and then alg/crv/typ must hold exactly the pinned values.
	header, err := parseStrictObject(headerBytes)
	if err != nil {
		return nil, ErrMalformed
	}
	for _, field := range []string{"alg", "typ", "kid", "crv"} {
		if _, ok := header[field].(string); !ok {
			return nil, ErrMalformed
		}
	}
	if header["alg"] != "EdDSA" || header["crv"] != "Ed25519" || header["typ"] != "GMT" {
		return nil, ErrMalformed
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
	// non-blank keys; anything else in a signed ent is malformed there and so must be here.
	for key, value := range ent {
		if strings.TrimSpace(key) == "" {
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
	ver, ok := claims["ver"].(int64)
	if !ok || ver != 1 {
		return nil, ErrMalformed // fail closed on an unknown format version
	}
	// exp is a REQUIRED key whose value may be null (perpetual). Absence is malformed —
	// never silently perpetual.
	expRaw, present := claims["exp"]
	if !present {
		return nil, ErrMalformed
	}
	if nbfRaw, hasNbf := claims["nbf"]; hasNbf && nbfRaw != nil {
		nbf, isInt := nbfRaw.(int64)
		if !isInt {
			return nil, ErrMalformed
		}
		if now < nbf {
			return nil, ErrNotYetValid
		}
	}
	if expRaw != nil {
		exp, isInt := expRaw.(int64)
		if !isInt {
			return nil, ErrMalformed
		}
		if now >= exp { // exp is exclusive
			return nil, ErrExpired
		}
	}
	return claims, nil
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
