use ed25519_dalek::SigningKey;
use grantmint_license_protocol::sign_token;
use serde_json::Value;

#[test]
fn signing_preserves_java_certificate_and_time_receipt_bytes() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../grantmint-core/src/test/resources/offline-device-v2.json"
    ))
    .unwrap();
    let hex = fixture["serverSeedHex"].as_str().unwrap();
    let seed: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let key = SigningKey::from_bytes(&seed.try_into().unwrap());
    for (typ, claims, token) in [
        ("GMT", "claims", "token"),
        ("GMT-TIME", "receiptClaims", "timeReceipt"),
    ] {
        assert_eq!(
            sign_token(&key, "fixture-signing-key", typ, &fixture[claims]).unwrap(),
            fixture[token]
        );
    }
}
