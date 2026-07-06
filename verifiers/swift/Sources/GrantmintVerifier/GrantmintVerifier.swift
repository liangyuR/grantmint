// Grantmint offline license verification — Swift (Apple CryptoKit).
//
// The executable counterpart of the verifier documented in docs/features/CLIENT_SDK.md, held to
// the Java reference implementation byte-for-byte by the pinned vector in
// docs/testing/CROSS_VERIFIER_FIXTURES.md.
//
// Licensed under the Apache License, Version 2.0 (like the Spring Boot starter — client-side
// code meant to be embedded in downstream, possibly closed-source, applications). See
// docs/security/OPERATOR_AND_LICENSE_NOTES.md.
//
// The wire contract this module enforces (docs/features/LICENSE_TOKEN_FORMAT.md):
//   1. exactly three non-empty dot-separated segments, each STRICT unpadded base64url — one text
//      form per byte string: '=' padding, the standard '+'/'/' alphabet, and non-zero unused
//      trailing bits are all malformed;
//   2. header carrying string alg/typ/kid/crv, pinned to alg=EdDSA, crv=Ed25519, typ=GMT before
//      any signature work;
//   3. Ed25519 signature over the ASCII bytes of the RECEIVED header.payload (never re-serialized);
//   4. strict payload JSON: duplicate member names and non-integer numbers are malformed
//      (JSONSerialization alone is last-wins on duplicates and reads floats — too lenient);
//      ver == 1; lid/kid/prd/pol/hld(n,e) required non-empty strings, iat a required integer,
//      ent a required object of flag | limit | string values; con (object) and seat (integer)
//      optional but never wrong-typed; exp a required key whose value may be null (perpetual);
//      nbf genuinely optional;
//   5. optional product binding: a caller-supplied expectedProduct must equal the authenticated
//      prd claim (wrongProduct), checked between the format-version gate and the temporal window
//      exactly like the reference — an expired sibling-product token is wrongProduct, never
//      expired in one verifier and wrongProduct in another;
//   6. now >= exp is expired (exp exclusive); now < nbf is not yet valid (nbf inclusive).

import CryptoKit
import Foundation

public enum LicenseError: Error, Equatable {
    /// `algNotAllowed` is the Java reference's ALG_NOT_ALLOWED (the header does not pin alg=EdDSA
    /// over crv=Ed25519 — an algorithm- or curve-confusion attempt) and `wrongType` its WRONG_TYPE
    /// (typ is not GMT — not a Grantmint license, e.g. a generic JWT); both are decided before any
    /// signature work, alg first, exactly like the Java, Go, and starter verifiers.
    /// `unsupportedVersion` is the reference's UNSUPPORTED_VERSION: an authentic token whose claims
    /// declare a format version this verifier does not know — rejected fail-closed with its own
    /// reason, so telemetry can tell "update the verifier" apart from a corrupt token. A wrong-typed
    /// or out-of-int32-range `ver` stays `malformed`, exactly like the reference.
    /// `wrongProduct` is the reference's WRONG_PRODUCT: an authentic token whose `prd` claim does
    /// not match the product the caller bound via `expectedProduct` — a sibling product's license
    /// signed by the same key pair, rejected after the format-version gate and before the temporal
    /// window.
    case malformed, algNotAllowed, wrongType, badSignature, unsupportedVersion, wrongProduct,
        expired, notYetValid, badKey
}

public struct VerifiedLicense {
    public let keyId: String
    public let licenseId: String
    public let product: String
    public let policy: String
    public let issuedAt: Date
    public let notBefore: Date?
    public let expiresAt: Date?
    public let entitlements: [String: Any]
}

/// Verifies a Grantmint signed token fully offline, as of `now` (epoch seconds, UTC).
/// `publicKeyBase64` is standard base64 of the 32-byte raw RFC 8032 Ed25519 public key —
/// printed by `grantmint keygen` when the key pair is created.
///
/// When `expectedProduct` is non-nil, the authenticated `prd` claim must equal it or the token is
/// rejected with `LicenseError.wrongProduct` — the Java reference's WRONG_PRODUCT, checked between
/// the format-version gate and the temporal window. This closes the cross-product acceptance gap
/// in a deployment where one Ed25519 key pair signs tokens for several products; pass nil to skip
/// the binding (the single-product case, where the embedded public key already scopes trust).
public func verifyLicense(
    _ token: String, publicKeyBase64: String, now: Int64, expectedProduct: String? = nil
) throws -> VerifiedLicense {
    guard let publicKeyRaw = Data(base64Encoded: publicKeyBase64), publicKeyRaw.count == 32,
        let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyRaw)
    else { throw LicenseError.badKey }

    // 1) Structure: three non-empty segments, each strict unpadded base64url.
    let parts = token.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3 else { throw LicenseError.malformed }
    let headerSeg = String(parts[0])
    let payloadSeg = String(parts[1])
    let signatureSeg = String(parts[2])
    guard let headerData = decodeBase64UrlStrict(headerSeg),
        let payloadData = decodeBase64UrlStrict(payloadSeg),
        let signature = decodeBase64UrlStrict(signatureSeg)
    else { throw LicenseError.malformed }

    // 2) Scheme + type pinning BEFORE the signature (closes JWT alg confusion). Like the Java
    //    reference, the header must carry all four fields as strings — a kid-less header is
    //    malformed — and alg/crv/typ must hold exactly the pinned values, each failure keeping the
    //    reference's distinct reason: ALG_NOT_ALLOWED first, then WRONG_TYPE.
    guard StrictJSONScan.isStrictObject(headerData),
        let header = (try? JSONSerialization.jsonObject(with: headerData)) as? [String: Any],
        header["kid"] as? String != nil,
        header["alg"] as? String != nil,
        header["crv"] as? String != nil,
        header["typ"] as? String != nil
    else { throw LicenseError.malformed }
    guard header["alg"] as? String == "EdDSA", header["crv"] as? String == "Ed25519" else {
        throw LicenseError.algNotAllowed
    }
    guard header["typ"] as? String == "GMT" else { throw LicenseError.wrongType }

    // 3) Ed25519 over the RECEIVED signing input — never a re-serialization.
    let signingInput = Data((headerSeg + "." + payloadSeg).utf8)
    guard signature.count == 64, key.isValidSignature(signature, for: signingInput) else {
        throw LicenseError.badSignature
    }

    // 4) The signature has spoken — now (and only now) trust and parse the payload, strictly.
    //    The claim table (LICENSE_TOKEN_FORMAT.md) marks lid/kid/prd/pol/hld/iat required — with
    //    non-empty strings — and ent a required object of flag | limit | string values under
    //    non-blank keys. Absence, a wrong type, or an empty required string is malformed, exactly
    //    like the Java, Go, and starter verifiers.
    guard StrictJSONScan.isStrictObject(payloadData),
        let obj = (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any]
    else { throw LicenseError.malformed }
    guard let kid = nonEmptyString(obj["kid"]),
        let lid = nonEmptyString(obj["lid"]),
        let prd = nonEmptyString(obj["prd"]),
        let pol = nonEmptyString(obj["pol"]),
        let hld = obj["hld"] as? [String: Any],
        nonEmptyString(hld["n"]) != nil, nonEmptyString(hld["e"]) != nil,
        let iat = try integerClaim(obj["iat"]),
        let ent = obj["ent"] as? [String: Any]
    else { throw LicenseError.malformed }
    for (entKey, entValue) in ent {
        guard !entKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
            entValue is NSNumber || entValue is String  // strict scan already banned floats
        else { throw LicenseError.malformed }
    }
    // exp is a REQUIRED key whose value may be null (perpetual). Absence is malformed — and a
    // present exp/nbf/seat with any non-integer, or a con that is not an object, is malformed
    // too, never silently ignored (a string exp would otherwise read as perpetual here while
    // every other verifier rejects the same bytes).
    guard obj.keys.contains("exp") else { throw LicenseError.malformed }
    let exp = try integerClaim(obj["exp"])  // nil when the value is JSON null (perpetual)
    let nbf = try integerClaim(obj["nbf"])
    // seat is a plain int in the spec's claim table, and the reference parses it with
    // Math.toIntExact — a value beyond the 32-bit range is malformed there, so it must be
    // malformed here too, never silently widened. (seat is not surfaced in VerifiedLicense;
    // this check exists purely for accept/reject parity.)
    if let seat = try integerClaim(obj["seat"]), seat < Int64(Int32.min) || seat > Int64(Int32.max) {
        throw LicenseError.malformed
    }
    if let conRaw = obj["con"], !(conRaw is NSNull), !(conRaw is [String: Any]) {
        throw LicenseError.malformed
    }

    // Format-version gate — after the claim table, before the temporal window, the same position
    // and the same granularity as the reference, starter, and Go verifiers: a wrong-typed or
    // out-of-int32-range ver is malformed like any other claim; a well-typed unknown version gets
    // its own reason.
    guard let ver = try integerClaim(obj["ver"]), ver >= Int64(Int32.min), ver <= Int64(Int32.max) else {
        throw LicenseError.malformed
    }
    guard ver == 1 else { throw LicenseError.unsupportedVersion }

    // 5) Product binding — an authentic token for a sibling product (same signing key pair) must
    //    not pass another product's gate. Sits between the version gate and the temporal window
    //    like the reference, so an expired sibling-product token reports wrongProduct here and
    //    WRONG_PRODUCT there — the same verdict for the same bytes.
    if let expectedProduct, prd != expectedProduct { throw LicenseError.wrongProduct }

    // 6) Temporal window: nbf inclusive, exp exclusive.
    if let nbf, now < nbf { throw LicenseError.notYetValid }
    if let exp, now >= exp { throw LicenseError.expired }

    return VerifiedLicense(
        keyId: kid,
        licenseId: lid,
        product: prd,
        policy: pol,
        issuedAt: Date(timeIntervalSince1970: TimeInterval(iat)),
        notBefore: nbf.map { Date(timeIntervalSince1970: TimeInterval($0)) },
        expiresAt: exp.map { Date(timeIntervalSince1970: TimeInterval($0)) },
        entitlements: ent)
}

/// An optional integer claim: an absent key or a JSON null reads as absent; any other non-integer
/// value is malformed. JSONSerialization bridges booleans to NSNumber, and Swift's dynamic cast
/// happily converts those to Int64 — but a signed `"ver":true` must be malformed here exactly as
/// it is for the Java reference, so booleans are told apart by their CoreFoundation type.
private func integerClaim(_ value: Any?) throws -> Int64? {
    guard let value, !(value is NSNull) else { return nil }
    guard let number = value as? NSNumber, CFGetTypeID(number as CFTypeRef) != CFBooleanGetTypeID() else {
        throw LicenseError.malformed
    }
    return number.int64Value  // the strict scan already banned fractions, exponents, and >64-bit
}

/// A required string claim per the table: present, a string, and non-empty — else the caller
/// treats it as malformed.
private func nonEmptyString(_ value: Any?) -> String? {
    guard let s = value as? String, !s.isEmpty else { return nil }
    return s
}

/// Strict unpadded base64url. The wire admits exactly ONE text form per byte string: URL-safe
/// alphabet, no '=', zero unused trailing bits in the final character. A lenient decoder that
/// ignored trailing bits would accept 15 alternate spellings of a 64-byte signature — and
/// disagree with the Java/Go verifiers on which strings are tokens.
func decodeBase64UrlStrict(_ s: String) -> Data? {
    guard !s.isEmpty, !s.contains("="), !s.contains("+"), !s.contains("/") else { return nil }
    var b = s.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while b.count % 4 != 0 { b.append("=") }  // re-pad only for Foundation's decoder
    guard let decoded = Data(base64Encoded: b) else { return nil }
    // Canonicality: re-encoding must reproduce the exact segment (rejects non-zero trailing bits).
    let reencoded = decoded.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return reencoded == s ? decoded : nil
}

/// Validates the wire's JSON strictness on the raw bytes BEFORE JSONSerialization extracts
/// values: duplicate object member names, non-integer numbers (fraction/exponent), integers
/// outside signed 64-bit, leading zeros, and trailing content are all malformed — exactly the
/// rules of the Java reference `CanonicalJson` / starter `StrictJson` readers.
enum StrictJSONScan {
    static func isStrictObject(_ data: Data) -> Bool {
        var scanner = Scanner(data)
        scanner.skipWhitespace()
        guard scanner.peek() == UInt8(ascii: "{"), scanner.value() else { return false }
        scanner.skipWhitespace()
        return scanner.atEnd
    }

    private struct Scanner {
        let bytes: [UInt8]
        var i = 0
        init(_ data: Data) { bytes = [UInt8](data) }
        var atEnd: Bool { i >= bytes.count }
        func peek() -> UInt8? { atEnd ? nil : bytes[i] }

        mutating func skipWhitespace() {
            while let c = peek(), c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D { i += 1 }
        }

        mutating func value() -> Bool {
            guard let c = peek() else { return false }
            switch c {
            case UInt8(ascii: "{"): return object()
            case UInt8(ascii: "["): return array()
            case UInt8(ascii: "\""): return string() != nil
            case UInt8(ascii: "t"): return literal("true")
            case UInt8(ascii: "f"): return literal("false")
            case UInt8(ascii: "n"): return literal("null")
            default: return number()
            }
        }

        mutating func object() -> Bool {
            i += 1  // '{'
            skipWhitespace()
            var keys = Set<String>()
            if peek() == UInt8(ascii: "}") {
                i += 1
                return true
            }
            while true {
                skipWhitespace()
                guard let key = string() else { return false }
                // Duplicates are undefined JSON and split parsers first- vs last-wins —
                // pinned as malformed so every SDK reads the same signed bytes identically.
                guard keys.insert(key).inserted else { return false }
                skipWhitespace()
                guard peek() == UInt8(ascii: ":") else { return false }
                i += 1
                skipWhitespace()
                guard value() else { return false }
                skipWhitespace()
                guard let c = peek() else { return false }
                i += 1
                if c == UInt8(ascii: "}") { return true }
                guard c == UInt8(ascii: ",") else { return false }
            }
        }

        mutating func array() -> Bool {
            i += 1  // '['
            skipWhitespace()
            if peek() == UInt8(ascii: "]") {
                i += 1
                return true
            }
            while true {
                skipWhitespace()
                guard value() else { return false }
                skipWhitespace()
                guard let c = peek() else { return false }
                i += 1
                if c == UInt8(ascii: "]") { return true }
                guard c == UInt8(ascii: ",") else { return false }
            }
        }

        mutating func string() -> String? {
            guard peek() == UInt8(ascii: "\"") else { return nil }
            i += 1
            var out = [UInt8]()
            while let c = peek() {
                i += 1
                if c == UInt8(ascii: "\"") { return String(decoding: out, as: UTF8.self) }
                if c < 0x20 { return nil }  // unescaped control character
                if c != UInt8(ascii: "\\") {
                    out.append(c)
                    continue
                }
                guard let escape = peek() else { return nil }
                i += 1
                switch escape {
                case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"): out.append(escape)
                case UInt8(ascii: "b"): out.append(0x08)
                case UInt8(ascii: "f"): out.append(0x0C)
                case UInt8(ascii: "n"): out.append(0x0A)
                case UInt8(ascii: "r"): out.append(0x0D)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "u"):
                    guard i + 4 <= bytes.count,
                        let hex = String(bytes: bytes[i..<i + 4], encoding: .utf8),
                        let scalarValue = UInt32(hex, radix: 16),
                        let scalar = Unicode.Scalar(scalarValue)
                    else { return nil }
                    i += 4
                    out.append(contentsOf: Array(String(scalar).utf8))
                default: return nil
                }
            }
            return nil  // unterminated string
        }

        mutating func literal(_ text: String) -> Bool {
            let expected = Array(text.utf8)
            guard i + expected.count <= bytes.count, Array(bytes[i..<i + expected.count]) == expected
            else { return false }
            i += expected.count
            return true
        }

        mutating func number() -> Bool {
            let start = i
            if peek() == UInt8(ascii: "-") { i += 1 }
            guard let first = peek(), first >= UInt8(ascii: "0"), first <= UInt8(ascii: "9") else { return false }
            if first == UInt8(ascii: "0") {
                i += 1
                if let next = peek(), next >= UInt8(ascii: "0"), next <= UInt8(ascii: "9") {
                    return false  // leading zero
                }
            } else {
                while let d = peek(), d >= UInt8(ascii: "0"), d <= UInt8(ascii: "9") { i += 1 }
            }
            if let next = peek(),
                next == UInt8(ascii: ".") || next == UInt8(ascii: "e") || next == UInt8(ascii: "E") {
                return false  // integers only — canonical JSON never emits a fraction/exponent
            }
            let literalText = String(decoding: bytes[start..<i], as: UTF8.self)
            return Int64(literalText) != nil  // must fit the signed 64-bit cross-language contract
        }
    }
}
