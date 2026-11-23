use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use grantmint_offline::*;
use serde_json::Value;

#[test]
fn java_pinned_device_certificate_and_time_receipt_verify_after_long_offline_period() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../grantmint-core/src/test/resources/offline-device-v2.json"
    ))
    .unwrap();
    let seed_hex = fixture["deviceSeedHex"].as_str().unwrap();
    let seed: Vec<u8> = (0..seed_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&seed_hex[i..i + 2], 16).unwrap())
        .collect();
    let device = DeviceIdentity::from_seed(seed.try_into().unwrap());
    let public: [u8; 32] = STANDARD
        .decode(fixture["serverPublicKey"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let keys: TrustedKeys = [("fixture-signing-key".into(), public)].into();
    let claims = &fixture["claims"];
    let receipt = &fixture["receiptClaims"];
    let expected = ExpectedDevice {
        product_id: claims["product_id"].as_str().unwrap(),
        license_id: claims["lid"].as_str().unwrap(),
        fingerprint_hash: claims["fingerprint_hash"].as_str().unwrap(),
        fingerprint_version: 1,
    };
    let now = receipt["server_time"].as_i64().unwrap();
    let challenge_id = receipt["challenge_id"].as_str().unwrap();
    let nonce = receipt["nonce"].as_str().unwrap();
    let message = format!(
        "grantmint.activate.v2\n{challenge_id}\n{nonce}\n{}\n{}\n{}\n{}\n1",
        expected.product_id,
        expected.license_id,
        device.public_key_base64(),
        expected.fingerprint_hash
    );
    let challenge = ActivationChallenge {
        challenge_id: challenge_id.into(),
        nonce: nonce.into(),
        message: URL_SAFE_NO_PAD.encode(message),
        expires_at: chrono::DateTime::from_timestamp(now + 300, 0)
            .unwrap()
            .to_rfc3339(),
    };
    let response = ActivationResponse {
        token: fixture["token"].as_str().unwrap().into(),
        revision: 1,
        binding_version: 1,
        server_time: now,
        time_receipt: fixture["timeReceipt"].as_str().unwrap().into(),
    };
    let activation =
        accept_activation(&response, &challenge, &keys, &expected, &device, now).unwrap();
    let offline = verify(
        &response.token,
        &keys,
        &expected,
        &device,
        &activation.state,
        now + 10 * 86_400,
        0,
    )
    .unwrap();
    assert!(offline.status.allows_new_work());
    assert!(offline.claims.ent["inspect"]["bool"].as_bool().unwrap());
    let deadline = claims["exp"].as_i64().unwrap();
    assert_eq!(
        verify(
            &response.token,
            &keys,
            &expected,
            &device,
            &offline.state,
            deadline,
            0
        )
        .unwrap()
        .status,
        Status::Expired
    );
}
