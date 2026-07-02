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
//   2. header pinned to alg=EdDSA, crv=Ed25519, typ=GMT before any signature work;
//   3. Ed25519 signature over the ASCII bytes of the RECEIVED header.payload (never re-serialized);
//   4. strict payload JSON: duplicate member names and non-integer numbers are malformed
//      (JSONSerialization alone is last-wins on duplicates and reads floats — too lenient);
//      ver == 1; lid/kid/prd/pol/hld(n,e)/iat required; exp a required key whose value may be
//      null (perpetual); nbf genuinely optional;
//   5. now >= exp is expired (exp exclusive); now < nbf is not yet valid (nbf inclusive).

import CryptoKit
import Foundation

public enum LicenseError: Error, Equatable {
    case malformed, badSignature, expired, notYetValid, badKey
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
public func verifyLicense(_ token: String, publicKeyBase64: String, now: Int64) throws -> VerifiedLicense {
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

    // 2) Scheme + type pinning BEFORE the signature (closes JWT alg confusion).
    guard StrictJSONScan.isStrictObject(headerData),
        let header = (try? JSONSerialization.jsonObject(with: headerData)) as? [String: Any],
        header["alg"] as? String == "EdDSA",
        header["crv"] as? String == "Ed25519",
        header["typ"] as? String == "GMT"
    else { throw LicenseError.malformed }

    // 3) Ed25519 over the RECEIVED signing input — never a re-serialization.
    let signingInput = Data((headerSeg + "." + payloadSeg).utf8)
    guard signature.count == 64, key.isValidSignature(signature, for: signingInput) else {
        throw LicenseError.badSignature
    }

    // 4) The signature has spoken — now (and only now) trust and parse the payload, strictly.
    guard StrictJSONScan.isStrictObject(payloadData),
        let obj = (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any],
        obj["ver"] as? Int64 == 1
    else { throw LicenseError.malformed }
    guard let kid = obj["kid"] as? String,
        let lid = obj["lid"] as? String,
        let prd = obj["prd"] as? String,
        let pol = obj["pol"] as? String,
        let hld = obj["hld"] as? [String: Any],
        hld["n"] as? String != nil, hld["e"] as? String != nil,
        let iat = obj["iat"] as? Int64
    else { throw LicenseError.malformed }
    // exp is a REQUIRED key whose value may be null (perpetual). Absence is malformed.
    guard obj.keys.contains("exp") else { throw LicenseError.malformed }
    let exp = obj["exp"] as? Int64  // nil when the value is JSON null (perpetual)
    let nbf = obj["nbf"] as? Int64

    // 5) Temporal window: nbf inclusive, exp exclusive.
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
        entitlements: obj["ent"] as? [String: Any] ?? [:])
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
