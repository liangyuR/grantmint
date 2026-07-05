// The Go half of the cross-verifier parity harness: verifies the pinned vector from
// docs/testing/CROSS_VERIFIER_FIXTURES.md and rejects every documented alternate encoding.
// The fixture's private seed is a published TEST vector (gitleaks:allow) — it signs nothing real.
package grantmint

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const (
	// The pinned vector — must match CROSS_VERIFIER_FIXTURES.md and both Java CrossVerifierFixtureTests.
	fixtureSeedHex   = "52ec811207633ad9f4a283d8eb887630e6183f7b6dfa8ea02fc4b9f9c7438aec" // gitleaks:allow
	fixturePublicHex = "34687417cc2f326d57e0a3702bb8bafda49bf8bdbb9f9ed224d0e0deb8be4101"
	fixtureIat       = int64(1751130000)
	fixtureExp       = int64(1782666000)
	fixtureToken     = "eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJHTUsxIiwidHlwIjoiR01UIn0." + // gitleaks:allow — published golden vector
		"eyJjb24iOnsibm9kZUxvY2tlZCI6dHJ1ZSwic2VhdHMiOjJ9LCJlbnQiOnsiYWlfYXNzaXN0Ijp0cnVlLCJtYXhfZGV2aWNlcyI6MiwibWF4X3Byb2plY3RzIjoxMCwidGVhbV9zeW5jIjp0cnVlLCJ0aWVyIjoicHJvIn0sImV4cCI6MTc4MjY2NjAwMCwiaGxkIjp7ImUiOiJqYW5lQGV4YW1wbGUuY29tIiwibiI6IkphbmUgRG9lIn0sImlhdCI6MTc1MTEzMDAwMCwia2lkIjoiSzdQMi05UVhNLTRUMUEiLCJsaWQiOiJsaWNfMDFKWjhYOVE0UjdNMkszUDVUNlY4VzBZMkEiLCJwb2wiOiJwb2xfcHJvX2FubnVhbCIsInByZCI6InByb2RfYWNtZV9ub3RlcyIsInNlYXQiOjIsInZlciI6MX0." +
		"dE2gDMZMeggftOMOeLjAK3fOu5Ax8b9DKSYSGb0N7pWoUZbZ43jdMRzrNTuQ734MsBGmFEi5bDoCFpJ0js8zDg"

	base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

func TestFixtureTokenVerifies(t *testing.T) {
	claims, err := Verify(fixtureToken, fixturePublicHex, fixtureIat)
	if err != nil {
		t.Fatalf("pinned fixture must verify at iat: %v", err)
	}
	if claims["kid"] != "K7P2-9QXM-4T1A" || claims["prd"] != "prod_acme_notes" {
		t.Fatalf("unexpected claims: kid=%v prd=%v", claims["kid"], claims["prd"])
	}
	if claims["exp"] != fixtureExp || claims["seat"] != int64(2) {
		t.Fatalf("unexpected claims: exp=%v seat=%v", claims["exp"], claims["seat"])
	}
	ent, ok := claims["ent"].(map[string]any)
	if !ok || ent["team_sync"] != true || ent["max_devices"] != int64(2) {
		t.Fatalf("unexpected entitlements: %v", claims["ent"])
	}
}

func TestExpiredAtExactlyExpAndAfter(t *testing.T) {
	// exp is exclusive: the token dies at the exp instant itself.
	for _, now := range []int64{fixtureExp, fixtureExp + 1} {
		if _, err := Verify(fixtureToken, fixturePublicHex, now); !errors.Is(err, ErrExpired) {
			t.Fatalf("at now=%d want ErrExpired, got %v", now, err)
		}
	}
	if _, err := Verify(fixtureToken, fixturePublicHex, fixtureExp-1); err != nil {
		t.Fatalf("one second before exp must still verify: %v", err)
	}
}

func TestNonCanonicalSignatureSpellingsAreMalformed(t *testing.T) {
	// The 86-char signature segment leaves 4 unused trailing bits: 15 alternate spellings decode
	// to the SAME signature bytes. Every one must be malformed — one text form per byte string.
	last := fixtureToken[len(fixtureToken)-1]
	value := strings.IndexByte(base64urlAlphabet, last)
	if value%16 != 0 {
		t.Fatalf("canonical final char %q must have zero trailing bits", last)
	}
	for bits := 1; bits <= 15; bits++ {
		spelled := fixtureToken[:len(fixtureToken)-1] + string(base64urlAlphabet[value|bits])
		if _, err := Verify(spelled, fixturePublicHex, fixtureIat); !errors.Is(err, ErrMalformed) {
			t.Fatalf("alternate spelling (bits=%d) must be malformed, got %v", bits, err)
		}
	}
}

func TestPaddedAndStandardAlphabetSegmentsAreMalformed(t *testing.T) {
	parts := strings.Split(fixtureToken, ".")
	padded := parts[0] + "=." + parts[1] + "." + parts[2]
	if _, err := Verify(padded, fixturePublicHex, fixtureIat); !errors.Is(err, ErrMalformed) {
		t.Fatalf("padded segment must be malformed, got %v", err)
	}
	standard := parts[0] + "." + parts[1] + ".+" + parts[2][1:] // '+' is standard base64, not URL-safe
	if _, err := Verify(standard, fixturePublicHex, fixtureIat); !errors.Is(err, ErrMalformed) {
		t.Fatalf("standard-alphabet segment must be malformed, got %v", err)
	}
}

func TestTamperedPayloadIsRejected(t *testing.T) {
	parts := strings.Split(fixtureToken, ".")
	tampered := []byte(parts[1])
	if tampered[10] == 'A' {
		tampered[10] = 'B'
	} else {
		tampered[10] = 'A'
	}
	token := parts[0] + "." + string(tampered) + "." + parts[2]
	if _, err := Verify(token, fixturePublicHex, fixtureIat); !errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrMalformed) {
		t.Fatalf("tampered payload must be rejected, got %v", err)
	}
}

func TestHeaderPinningIsRejectedBeforeSignatureWithDistinctReasons(t *testing.T) {
	// A pinning failure must surface even with a garbage signature — proof the header pin runs
	// before any signature work — and must keep the Java reference's distinct reason: a scheme or
	// curve confusion is ALG_NOT_ALLOWED, a foreign typ is WRONG_TYPE, and the alg gate runs first.
	cases := map[string]struct {
		headerJSON string
		want       error
	}{
		"alg=none":          {`{"alg":"none","crv":"Ed25519","kid":"GMK1","typ":"GMT"}`, ErrAlgNotAllowed},
		"alg=HS256":         {`{"alg":"HS256","crv":"Ed25519","kid":"GMK1","typ":"GMT"}`, ErrAlgNotAllowed},
		"curve confusion":   {`{"alg":"EdDSA","crv":"Ed448","kid":"GMK1","typ":"GMT"}`, ErrAlgNotAllowed},
		"foreign typ (JWT)": {`{"alg":"EdDSA","crv":"Ed25519","kid":"GMK1","typ":"JWT"}`, ErrWrongType},
		"alg gate runs 1st": {`{"alg":"none","crv":"Ed25519","kid":"GMK1","typ":"JWT"}`, ErrAlgNotAllowed},
	}
	payload := strings.Split(fixtureToken, ".")[1]
	for name, tc := range cases {
		header := b64.EncodeToString([]byte(tc.headerJSON))
		token := header + "." + payload + "." + b64.EncodeToString(make([]byte, 64))
		if _, err := Verify(token, fixturePublicHex, fixtureIat); !errors.Is(err, tc.want) {
			t.Fatalf("%s: want %v before the signature is touched, got %v", name, tc.want, err)
		}
	}
}

// signRaw mints a token from raw JSON under the fixture's published test seed — for adversarial
// shapes the canonical issuer refuses to produce (duplicate keys, floats, a missing exp).
func signRaw(t *testing.T, headerJSON, payloadJSON string) string {
	t.Helper()
	seed, err := hex.DecodeString(fixtureSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	enc := base64.RawURLEncoding
	headerSeg := enc.EncodeToString([]byte(headerJSON))
	payloadSeg := enc.EncodeToString([]byte(payloadJSON))
	sig := ed25519.Sign(key, []byte(headerSeg+"."+payloadSeg))
	return headerSeg + "." + payloadSeg + "." + enc.EncodeToString(sig)
}

const pinnedHeaderJSON = `{"alg":"EdDSA","crv":"Ed25519","kid":"GMK1","typ":"GMT"}`

// requiredTail carries every required claim except exp and ver, so each adversarial case below
// isolates exactly one defect (mirrors the Swift and starter parity suites).
const requiredTail = `"ent":{},"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p"`

func TestValidlySignedButNonStrictPayloadsAreMalformed(t *testing.T) {
	cases := map[string]string{
		"duplicate key":     `{"exp":null,"exp":null,` + requiredTail + `,"ver":1}`,
		"float exp":         `{"exp":1.5,` + requiredTail + `,"ver":1}`,
		"exponent number":   `{"exp":2e9,` + requiredTail + `,"ver":1}`,
		"oversized integer": `{"exp":99999999999999999999,` + requiredTail + `,"ver":1}`,
		"string exp":        `{"exp":"1782666000",` + requiredTail + `,"ver":1}`,
		"missing exp":       `{` + requiredTail + `,"ver":1}`,
		"trailing content":  `{"exp":null,` + requiredTail + `,"ver":1} {}`,
		// A ver beyond int32 is a malformed claim (the reference parses ver as an int), NOT a
		// future format version — only a well-typed in-range unknown version gets its own reason
		// (see TestUnknownFormatVersionIsUnsupportedNotMalformed).
		"ver beyond int32":    `{"exp":null,` + requiredTail + `,"ver":5000000000}`,
		"non-object toplevel": `[1,2,3]`,
		"missing pol/hld/iat": `{"ent":{},"exp":null,"kid":"K","lid":"l","prd":"p","ver":1}`,
		"missing ent":         `{"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}`,
		"ent not an object":   `{"ent":42,"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}`,
		"empty prd":           `{"ent":{},"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"","ver":1}`,
		"empty holder email":  `{"ent":{},"exp":null,"hld":{"e":"","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}`,
		"con not an object":   `{"con":7,"exp":null,` + requiredTail + `,"ver":1}`,
		"seat not an integer": `{"exp":null,` + requiredTail + `,"seat":"two","ver":1}`,
		// seat is an int in the claim table; the reference parses it with Math.toIntExact, so an
		// int64 outside the 32-bit range is malformed there and must be malformed here too — the
		// M13 audit's surviving 3-vs-1 parity split.
		"seat beyond int32":          `{"exp":null,` + requiredTail + `,"seat":5000000000,"ver":1}`,
		"seat beyond negative int32": `{"exp":null,` + requiredTail + `,"seat":-5000000000,"ver":1}`,
		// Adversarial shapes the Swift suite pins that Go is structurally immune to (encoding/json
		// yields distinct types) — pinned anyway so the four suites assert the same vectors.
		"boolean ver":     `{"exp":null,` + requiredTail + `,"ver":true}`,
		"ent array value": `{"ent":{"tier":[1,2]},"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}`,
	}
	for name, payloadJSON := range cases {
		token := signRaw(t, pinnedHeaderJSON, payloadJSON)
		if _, err := Verify(token, fixturePublicHex, fixtureIat); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%s: want ErrMalformed, got %v", name, err)
		}
	}
}

// 2026-07-05 audit (GRANTMINT-148): an authentic token from a future format version keeps the
// reference's distinct UNSUPPORTED_VERSION reason — still rejected, but telemetry can tell
// "update the verifier" apart from a corrupt token, like the Java verifiers do.
func TestUnknownFormatVersionIsUnsupportedNotMalformed(t *testing.T) {
	token := signRaw(t, pinnedHeaderJSON, `{"exp":null,`+requiredTail+`,"ver":2}`)
	if _, err := Verify(token, fixturePublicHex, fixtureIat); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("ver=2: want ErrUnsupportedVersion, got %v", err)
	}
}

func TestHeaderMissingKidIsMalformed(t *testing.T) {
	// The reference decodeHeader requires all four header fields as strings; a validly-signed
	// token whose header drops kid must be malformed here too.
	token := signRaw(t, `{"alg":"EdDSA","crv":"Ed25519","typ":"GMT"}`, `{"exp":null,`+requiredTail+`,"ver":1}`)
	if _, err := Verify(token, fixturePublicHex, fixtureIat); !errors.Is(err, ErrMalformed) {
		t.Fatalf("kid-less header must be malformed, got %v", err)
	}
}

func TestPerpetualNullExpNeverExpires(t *testing.T) {
	token := signRaw(t, pinnedHeaderJSON, `{"exp":null,`+requiredTail+`,"ver":1}`)
	if _, err := Verify(token, fixturePublicHex, 4102444800); err != nil { // year 2100
		t.Fatalf("perpetual license must verify far in the future: %v", err)
	}
}

func TestNbfGate(t *testing.T) {
	token := signRaw(t, pinnedHeaderJSON, `{"exp":null,`+requiredTail+`,"nbf":1000,"ver":1}`)
	if _, err := Verify(token, fixturePublicHex, 999); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("before nbf must be not-yet-valid, got %v", err)
	}
	if _, err := Verify(token, fixturePublicHex, 1000); err != nil { // nbf is inclusive
		t.Fatalf("at nbf must verify: %v", err)
	}
}
