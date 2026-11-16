use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use grantmint_offline::*;
use serde_json::{json, Value};

const PRODUCT: &str = "00000000-0000-4000-8000-000000000001";
const LICENSE: &str = "00000000-0000-4000-8000-000000000002";
const OTHER: &str = "00000000-0000-4000-8000-000000000003";
const IAT: i64 = 1_800_000_000;
const EXP: i64 = IAT + 30 * 86_400;

fn context(fp: &str) -> ExpectedDevice<'_> {
    ExpectedDevice {
        product_id: PRODUCT,
        license_id: LICENSE,
        fingerprint_hash: fp,
        fingerprint_version: 1,
    }
}
fn keys() -> TrustedKeys {
    [(
        "test-key".into(),
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    )]
    .into()
}
fn state(device: &DeviceIdentity) -> VerificationState {
    VerificationState {
        product_id: PRODUCT.into(),
        license_id: LICENSE.into(),
        device_key_hash: device.key_hash(),
        revision: 1,
        binding_version: 1,
        max_seen_time: IAT,
    }
}
fn payload(device: &DeviceIdentity, fp: &str) -> Value {
    json!({"ver":2,"mode":"offline_device","lid":LICENSE,"kid":"TEST-LICENSE","product_id":PRODUCT,"prd":"test-product","serial":OTHER,
        "revision":1,"binding_version":1,"device_key_hash":device.key_hash(),"fingerprint_hash":fp,"fingerprint_version":1,
        "iat":IAT,"nbf":IAT,"exp":EXP,"ent":{"inspect":{"bool":true}},"seat":1})
}
fn sign_raw(payload: &str, typ: &str) -> String {
    let header = URL_SAFE_NO_PAD
        .encode(json!({"alg":"EdDSA","crv":"Ed25519","typ":typ,"kid":"test-key"}).to_string());
    let body = URL_SAFE_NO_PAD.encode(payload);
    let message = format!("{header}.{body}");
    let signature = SigningKey::from_bytes(&[7; 32]).sign(message.as_bytes());
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

#[test]
fn signed_device_license_has_exact_warning_and_expiry_boundaries_without_network() {
    let device = DeviceIdentity::from_seed([8; 32]);
    let fp = URL_SAFE_NO_PAD.encode([9; 32]);
    let token = sign_raw(&payload(&device, &fp).to_string(), "GMT");
    for (now, status) in [
        (EXP - 604_801, Status::Valid),
        (EXP - 604_800, Status::Expiring),
        (EXP - 1, Status::Expiring),
        (EXP, Status::Expired),
    ] {
        let result = verify(
            &token,
            &keys(),
            &context(&fp),
            &device,
            &state(&device),
            now,
            0,
        )
        .unwrap();
        assert_eq!(result.status, status);
        assert_eq!(result.state.max_seen_time, now);
    }
}

#[test]
fn copying_token_cannot_change_product_license_device_or_fingerprint() {
    let device = DeviceIdentity::from_seed([8; 32]);
    let fp = URL_SAFE_NO_PAD.encode([9; 32]);
    let token = sign_raw(&payload(&device, &fp).to_string(), "GMT");
    let wrong_product = ExpectedDevice {
        product_id: OTHER,
        ..context(&fp)
    };
    let wrong_license = ExpectedDevice {
        license_id: OTHER,
        ..context(&fp)
    };
    let wrong_fp = URL_SAFE_NO_PAD.encode([10; 32]);
    for (ctx, identity, error) in [
        (wrong_product, &device, Error::WrongProduct),
        (wrong_license, &device, Error::WrongLicense),
        (context(&wrong_fp), &device, Error::WrongFingerprint),
    ] {
        assert_eq!(
            verify(&token, &keys(), &ctx, identity, &state(&device), IAT, 0).unwrap_err(),
            error
        );
    }
    assert_eq!(
        verify(
            &token,
            &keys(),
            &context(&fp),
            &DeviceIdentity::from_seed([11; 32]),
            &state(&device),
            IAT,
            0
        )
        .unwrap_err(),
        Error::WrongDevice
    );
}

#[test]
fn old_revision_and_binding_are_rejected_even_with_a_valid_signature() {
    let device = DeviceIdentity::from_seed([8; 32]);
    let fp = URL_SAFE_NO_PAD.encode([9; 32]);
    let token = sign_raw(&payload(&device, &fp).to_string(), "GMT");
    for field in ["revision", "binding"] {
        let mut persisted = state(&device);
        if field == "revision" {
            persisted.revision = 2
        } else {
            persisted.binding_version = 2
        }
        assert_eq!(
            verify(&token, &keys(), &context(&fp), &device, &persisted, IAT, 0).unwrap_err(),
            Error::Rollback
        );
    }
}

#[test]
fn backwards_clock_is_rejected_and_tolerance_cannot_extend_expiry() {
    let device = DeviceIdentity::from_seed([8; 32]);
    let fp = URL_SAFE_NO_PAD.encode([9; 32]);
    let token = sign_raw(&payload(&device, &fp).to_string(), "GMT");
    let persisted = VerificationState {
        max_seen_time: EXP,
        ..state(&device)
    };
    assert_eq!(
        verify(
            &token,
            &keys(),
            &context(&fp),
            &device,
            &persisted,
            EXP - 301,
            0
        )
        .unwrap_err(),
        Error::ClockSuspect
    );
    assert_eq!(
        verify(
            &token,
            &keys(),
            &context(&fp),
            &device,
            &persisted,
            EXP - 300,
            0
        )
        .unwrap()
        .status,
        Status::Expired
    );
    let anchor = VerificationState {
        max_seen_time: EXP - 10,
        ..state(&device)
    };
    assert_eq!(
        verify(
            &token,
            &keys(),
            &context(&fp),
            &device,
            &anchor,
            EXP - 10,
            10
        )
        .unwrap()
        .status,
        Status::Expired
    );
}

#[test]
fn validly_signed_legacy_ambiguous_and_incomplete_claims_are_rejected() {
    let device = DeviceIdentity::from_seed([8; 32]);
    let fp = URL_SAFE_NO_PAD.encode([9; 32]);
    let baseline = payload(&device, &fp);
    for field in ["ver", "seat", "fingerprint_version"] {
        let mut invalid = baseline.clone();
        invalid[field] = json!(if field == "ver" { 1 } else { 2 });
        let token = sign_raw(&invalid.to_string(), "GMT");
        assert_eq!(
            verify(
                &token,
                &keys(),
                &context(&fp),
                &device,
                &state(&device),
                IAT,
                0
            )
            .unwrap_err(),
            Error::Unsupported
        );
    }
    let mut missing = baseline.clone();
    missing.as_object_mut().unwrap().remove("exp");
    let null_exp = {
        let mut v = baseline.clone();
        v["exp"] = Value::Null;
        v
    };
    let fractional = baseline
        .to_string()
        .replace("\"revision\":1", "\"revision\":1.0");
    let duplicate = baseline.to_string().replacen('{', "{\"revision\":1,", 1);
    for invalid in [
        missing.to_string(),
        null_exp.to_string(),
        fractional,
        duplicate,
    ] {
        assert_eq!(
            verify(
                &sign_raw(&invalid, "GMT"),
                &keys(),
                &context(&fp),
                &device,
                &state(&device),
                IAT,
                0
            )
            .unwrap_err(),
            Error::Malformed
        );
    }
}

#[test]
fn modified_payload_cannot_reuse_signature_and_untrusted_keys_are_not_accepted() {
    let device = DeviceIdentity::from_seed([8; 32]);
    let fp = URL_SAFE_NO_PAD.encode([9; 32]);
    let original = payload(&device, &fp);
    let token = sign_raw(&original.to_string(), "GMT");
    let parts: Vec<_> = token.split('.').collect();
    let mut edited = original;
    edited["exp"] = json!(EXP + 86_400);
    let altered = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(edited.to_string()),
        parts[2]
    );
    assert_eq!(
        verify(
            &altered,
            &keys(),
            &context(&fp),
            &device,
            &state(&device),
            IAT,
            0
        )
        .unwrap_err(),
        Error::InvalidSignature
    );
    assert_eq!(
        verify(
            &token,
            &TrustedKeys::new(),
            &context(&fp),
            &device,
            &state(&device),
            IAT,
            0
        )
        .unwrap_err(),
        Error::UnknownKey
    );
}

#[test]
fn time_anchor_requires_matching_signed_nonce_and_certificate() {
    let device = DeviceIdentity::from_seed([8; 32]);
    let fp = URL_SAFE_NO_PAD.encode([9; 32]);
    let nonce = URL_SAFE_NO_PAD.encode([4; 32]);
    let message = format!(
        "grantmint.activate.v2\n{OTHER}\n{nonce}\n{PRODUCT}\n{LICENSE}\n{}\n{fp}\n1",
        device.public_key_base64()
    );
    let challenge = ActivationChallenge {
        challenge_id: OTHER.into(),
        nonce: nonce.clone(),
        message: URL_SAFE_NO_PAD.encode(message),
        expires_at: chrono::DateTime::from_timestamp(IAT + 300, 0)
            .unwrap()
            .to_rfc3339(),
    };
    let receipt = json!({"ver":2,"operation":"activate","challenge_id":OTHER,"nonce":nonce,"product_id":PRODUCT,"lid":LICENSE,"device_key_hash":device.key_hash(),"serial":OTHER,"server_time":IAT});
    let mut response = ActivationResponse {
        token: sign_raw(&payload(&device, &fp).to_string(), "GMT"),
        revision: 1,
        binding_version: 1,
        server_time: IAT,
        time_receipt: sign_raw(&receipt.to_string(), "GMT-TIME"),
    };
    let accepted =
        accept_activation(&response, &challenge, &keys(), &context(&fp), &device, IAT).unwrap();
    assert_eq!(accepted.state.max_seen_time, IAT);
    let mut replay = receipt;
    replay["nonce"] = json!(URL_SAFE_NO_PAD.encode([5; 32]));
    response.time_receipt = sign_raw(&replay.to_string(), "GMT-TIME");
    assert_eq!(
        accept_activation(&response, &challenge, &keys(), &context(&fp), &device, IAT).unwrap_err(),
        Error::InvalidChallenge
    );
    let wrong = ExpectedDevice {
        license_id: OTHER,
        ..context(&fp)
    };
    assert_eq!(
        sign_activation_challenge(&challenge, &wrong, &device, IAT).unwrap_err(),
        Error::InvalidChallenge
    );
}

#[test]
fn excessive_or_noncanonical_untrusted_input_fails_before_use() {
    let excessive = format!("{}0{}", "[".repeat(140), "]".repeat(140));
    for bytes in [
        excessive.as_bytes(),
        b"{\"a\":{\"x\":1,\"x\":2}}",
        b"{\"a\":1e0}",
        b"{\"a\":9223372036854775808}",
    ] {
        assert_eq!(parse_strict_json(bytes).unwrap_err(), Error::Malformed);
    }
    let device = DeviceIdentity::from_seed([8; 32]);
    let fp = URL_SAFE_NO_PAD.encode([9; 32]);
    let token = sign_raw(&payload(&device, &fp).to_string(), "GMT");
    for malformed in [format!("{token}="), "x".repeat(131_073)] {
        assert_eq!(
            verify(
                &malformed,
                &keys(),
                &context(&fp),
                &device,
                &state(&device),
                IAT,
                0
            )
            .unwrap_err(),
            Error::Malformed
        );
    }
}
