// The Swift half of the cross-verifier parity harness: verifies the pinned vector from
// docs/testing/CROSS_VERIFIER_FIXTURES.md and rejects every documented alternate encoding.
// The fixture's private seed is a published TEST vector (gitleaks:allow) — it signs nothing real.
import CryptoKit
import XCTest

@testable import GrantmintVerifier

final class GrantmintVerifierTests: XCTestCase {

    // The pinned vector — must match CROSS_VERIFIER_FIXTURES.md and both Java CrossVerifierFixtureTests.
    static let seedHex = "52ec811207633ad9f4a283d8eb887630e6183f7b6dfa8ea02fc4b9f9c7438aec"  // gitleaks:allow
    static let publicHex = "34687417cc2f326d57e0a3702bb8bafda49bf8bdbb9f9ed224d0e0deb8be4101"
    static let iat: Int64 = 1_751_130_000
    static let exp: Int64 = 1_782_666_000
    static let token =
        "eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJHTUsxIiwidHlwIjoiR01UIn0."  // gitleaks:allow — published golden vector
        + "eyJjb24iOnsibm9kZUxvY2tlZCI6dHJ1ZSwic2VhdHMiOjJ9LCJlbnQiOnsiYWlfYXNzaXN0Ijp0cnVlLCJtYXhfZGV2aWNlcyI6MiwibWF4X3Byb2plY3RzIjoxMCwidGVhbV9zeW5jIjp0cnVlLCJ0aWVyIjoicHJvIn0sImV4cCI6MTc4MjY2NjAwMCwiaGxkIjp7ImUiOiJqYW5lQGV4YW1wbGUuY29tIiwibiI6IkphbmUgRG9lIn0sImlhdCI6MTc1MTEzMDAwMCwia2lkIjoiSzdQMi05UVhNLTRUMUEiLCJsaWQiOiJsaWNfMDFKWjhYOVE0UjdNMkszUDVUNlY4VzBZMkEiLCJwb2wiOiJwb2xfcHJvX2FubnVhbCIsInByZCI6InByb2RfYWNtZV9ub3RlcyIsInNlYXQiOjIsInZlciI6MX0."
        + "dE2gDMZMeggftOMOeLjAK3fOu5Ax8b9DKSYSGb0N7pWoUZbZ43jdMRzrNTuQ734MsBGmFEi5bDoCFpJ0js8zDg"

    static let base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    static var publicKeyBase64: String { data(hex: publicHex).base64EncodedString() }

    static func data(hex: String) -> Data {
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return Data(bytes)
    }

    /// Mint a token from raw JSON under the fixture's published test seed — for adversarial
    /// shapes the canonical issuer refuses to produce (duplicate keys, floats, a missing exp).
    static func signRaw(headerJSON: String, payloadJSON: String) throws -> String {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: data(hex: seedHex))
        func b64url(_ raw: Data) -> String {
            raw.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let headerSeg = b64url(Data(headerJSON.utf8))
        let payloadSeg = b64url(Data(payloadJSON.utf8))
        let signature = try key.signature(for: Data((headerSeg + "." + payloadSeg).utf8))
        return headerSeg + "." + payloadSeg + "." + b64url(signature)
    }

    static let pinnedHeaderJSON = #"{"alg":"EdDSA","crv":"Ed25519","kid":"GMK1","typ":"GMT"}"#

    private func assertThrows(_ token: String, _ expected: LicenseError, at now: Int64 = iat,
        _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(
            try verifyLicense(token, publicKeyBase64: Self.publicKeyBase64, now: now),
            message, file: file, line: line
        ) { error in
            XCTAssertEqual(error as? LicenseError, expected, message, file: file, line: line)
        }
    }

    func testFixtureTokenVerifies() throws {
        let lic = try verifyLicense(Self.token, publicKeyBase64: Self.publicKeyBase64, now: Self.iat)
        XCTAssertEqual(lic.keyId, "K7P2-9QXM-4T1A")
        XCTAssertEqual(lic.product, "prod_acme_notes")
        XCTAssertEqual(lic.policy, "pol_pro_annual")
        XCTAssertEqual(lic.expiresAt, Date(timeIntervalSince1970: TimeInterval(Self.exp)))
        XCTAssertEqual(lic.entitlements["team_sync"] as? Bool, true)
        XCTAssertEqual(lic.entitlements["max_devices"] as? Int64, 2)
        XCTAssertEqual(lic.entitlements["tier"] as? String, "pro")
    }

    func testExpiredAtExactlyExpAndAfter() throws {
        // exp is exclusive: the token dies at the exp instant itself.
        assertThrows(Self.token, .expired, at: Self.exp)
        assertThrows(Self.token, .expired, at: Self.exp + 1)
        XCTAssertNoThrow(try verifyLicense(Self.token, publicKeyBase64: Self.publicKeyBase64, now: Self.exp - 1))
    }

    func testNonCanonicalSignatureSpellingsAreMalformed() {
        // The 86-char signature segment leaves 4 unused trailing bits: 15 alternate spellings
        // decode to the SAME signature bytes. Every one must be malformed.
        let alphabet = Array(Self.base64urlAlphabet)
        let last = Self.token.last!
        let value = alphabet.firstIndex(of: last)!
        XCTAssertEqual(value % 16, 0, "canonical final char must have zero trailing bits")
        for bits in 1...15 {
            let spelled = String(Self.token.dropLast()) + String(alphabet[value | bits])
            assertThrows(spelled, .malformed, "alternate spelling bits=\(bits)")
        }
    }

    func testPaddedAndStandardAlphabetSegmentsAreMalformed() {
        let parts = Self.token.split(separator: ".").map(String.init)
        assertThrows(parts[0] + "=." + parts[1] + "." + parts[2], .malformed, "padded segment")
        assertThrows(parts[0] + "." + parts[1] + ".+" + parts[2].dropFirst(), .malformed, "standard alphabet")
    }

    func testTamperedPayloadIsRejected() {
        let parts = Self.token.split(separator: ".").map(String.init)
        var payload = Array(parts[1])
        payload[10] = payload[10] == "A" ? "B" : "A"
        assertThrows(parts[0] + "." + String(payload) + "." + parts[2], .badSignature)
    }

    func testHeaderPinningIsRejectedBeforeSignatureWithDistinctReasons() throws {
        // A pinning failure must surface even with a garbage signature — proof the header pin runs
        // before any signature work — and must keep the Java reference's distinct reason: a scheme
        // or curve confusion is ALG_NOT_ALLOWED, a foreign typ is WRONG_TYPE, and alg gates first.
        func b64url(_ raw: Data) -> String {
            raw.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let cases: [(String, String, LicenseError)] = [
            ("alg=none", #"{"alg":"none","crv":"Ed25519","kid":"GMK1","typ":"GMT"}"#, .algNotAllowed),
            ("alg=HS256", #"{"alg":"HS256","crv":"Ed25519","kid":"GMK1","typ":"GMT"}"#, .algNotAllowed),
            ("curve confusion", #"{"alg":"EdDSA","crv":"Ed448","kid":"GMK1","typ":"GMT"}"#, .algNotAllowed),
            ("foreign typ (JWT)", #"{"alg":"EdDSA","crv":"Ed25519","kid":"GMK1","typ":"JWT"}"#, .wrongType),
            ("alg gate runs first", #"{"alg":"none","crv":"Ed25519","kid":"GMK1","typ":"JWT"}"#, .algNotAllowed),
        ]
        let payload = Self.token.split(separator: ".").map(String.init)[1]
        let garbageSig = b64url(Data(count: 64))
        for (name, headerJSON, expected) in cases {
            let header = b64url(Data(headerJSON.utf8))
            assertThrows(header + "." + payload + "." + garbageSig, expected, name)
        }
    }

    // Every required claim except exp and ver, so each adversarial case isolates one defect.
    static let requiredTail =
        #""ent":{},"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p""#

    func testValidlySignedButNonStrictPayloadsAreMalformed() throws {
        let requiredTail = Self.requiredTail
        let cases: [(String, String)] = [
            ("duplicate key", #"{"exp":null,"exp":null,"# + requiredTail + #","ver":1}"#),
            ("float exp", #"{"exp":1.5,"# + requiredTail + #","ver":1}"#),
            ("exponent number", #"{"exp":2e9,"# + requiredTail + #","ver":1}"#),
            ("oversized integer", #"{"exp":99999999999999999999,"# + requiredTail + #","ver":1}"#),
            ("string exp", #"{"exp":"1782666000","# + requiredTail + #","ver":1}"#),
            ("missing exp", "{" + requiredTail + #","ver":1}"#),
            ("boolean ver", #"{"exp":null,"# + requiredTail + #","ver":true}"#),
            // A ver beyond int32 is a malformed claim (the reference parses ver as an int), NOT a
            // future format version — only a well-typed in-range unknown version gets its own
            // reason (see testUnknownFormatVersionIsUnsupportedNotMalformed).
            ("ver beyond int32", #"{"exp":null,"# + requiredTail + #","ver":5000000000}"#),
            ("missing pol/hld/iat", #"{"ent":{},"exp":null,"kid":"K","lid":"l","prd":"p","ver":1}"#),
            (
                "missing ent",
                #"{"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}"#
            ),
            (
                "ent not an object",
                #"{"ent":42,"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}"#
            ),
            (
                "ent value not a scalar",
                #"{"ent":{"tiers":[1,2]},"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}"#
            ),
            (
                "empty prd",
                #"{"ent":{},"exp":null,"hld":{"e":"e","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"","ver":1}"#
            ),
            (
                "empty holder email",
                #"{"ent":{},"exp":null,"hld":{"e":"","n":"n"},"iat":1751130000,"kid":"K","lid":"l","pol":"po","prd":"p","ver":1}"#
            ),
            ("con not an object", #"{"con":7,"exp":null,"# + requiredTail + #","ver":1}"#),
            ("seat not an integer", #"{"exp":null,"# + requiredTail + #","seat":"two","ver":1}"#),
            // seat is an int in the claim table; the reference parses it with Math.toIntExact, so
            // an int64 outside the 32-bit range is malformed there and must be malformed here too —
            // the M13 audit's surviving 3-vs-1 parity split.
            ("seat beyond int32", #"{"exp":null,"# + requiredTail + #","seat":5000000000,"ver":1}"#),
            (
                "seat beyond negative int32",
                #"{"exp":null,"# + requiredTail + #","seat":-5000000000,"ver":1}"#
            ),
            ("trailing content", #"{"exp":null,"# + requiredTail + #","ver":1} {}"#),
        ]
        for (name, payloadJSON) in cases {
            let token = try Self.signRaw(headerJSON: Self.pinnedHeaderJSON, payloadJSON: payloadJSON)
            assertThrows(token, .malformed, name)
        }
    }

    func testUnknownFormatVersionIsUnsupportedNotMalformed() throws {
        // 2026-07-05 audit (GRANTMINT-148): an authentic token from a future format version keeps
        // the reference's distinct UNSUPPORTED_VERSION reason — still rejected, but telemetry can
        // tell "update the verifier" apart from a corrupt token, like the Java verifiers do.
        let token = try Self.signRaw(
            headerJSON: Self.pinnedHeaderJSON,
            payloadJSON: #"{"exp":null,"# + Self.requiredTail + #","ver":2}"#)
        assertThrows(token, .unsupportedVersion, "unknown ver")
    }

    func testHeaderMissingKidIsMalformed() throws {
        // The reference decodeHeader requires all four header fields as strings; a validly-signed
        // token whose header drops kid must be malformed here too.
        let token = try Self.signRaw(
            headerJSON: #"{"alg":"EdDSA","crv":"Ed25519","typ":"GMT"}"#,
            payloadJSON: #"{"exp":null,"# + Self.requiredTail + #","ver":1}"#)
        assertThrows(token, .malformed, "kid-less header")
    }

    func testPerpetualNullExpNeverExpires() throws {
        let payload = #"{"exp":null,"# + Self.requiredTail + #","ver":1}"#
        let token = try Self.signRaw(headerJSON: Self.pinnedHeaderJSON, payloadJSON: payload)
        XCTAssertNoThrow(
            try verifyLicense(token, publicKeyBase64: Self.publicKeyBase64, now: 4_102_444_800))  // year 2100
    }

    func testNbfGate() throws {
        let payload = #"{"exp":null,"# + Self.requiredTail + #","nbf":1000,"ver":1}"#
        let token = try Self.signRaw(headerJSON: Self.pinnedHeaderJSON, payloadJSON: payload)
        assertThrows(token, .notYetValid, at: 999)
        XCTAssertNoThrow(try verifyLicense(token, publicKeyBase64: Self.publicKeyBase64, now: 1000))  // nbf inclusive
    }
}
