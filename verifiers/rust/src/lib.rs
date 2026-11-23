use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};

use grantmint_license_protocol::{activation_message, operation_message, ChallengeContext};
pub use grantmint_license_protocol::{
    ActivationChallenge, DeviceChallenge, Operation, TokenResponse as ActivationResponse,
};

const MAX_TOKEN_BYTES: usize = 131_072;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
pub type TrustedKeys = BTreeMap<String, [u8; 32]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Malformed,
    Unsupported,
    UnknownKey,
    InvalidSignature,
    WrongProduct,
    WrongLicense,
    WrongDevice,
    WrongFingerprint,
    Rollback,
    ClockSuspect,
    NotYetValid,
    InvalidChallenge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

pub struct DeviceIdentity(SigningKey);
impl DeviceIdentity {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.public_key())
    }
    pub fn key_hash(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.public_key()))
    }
}

pub struct ExpectedDevice<'a> {
    pub product_id: &'a str,
    pub license_id: &'a str,
    pub fingerprint_hash: &'a str,
    pub fingerprint_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationState {
    pub product_id: String,
    pub license_id: String,
    pub device_key_hash: String,
    pub revision: i64,
    pub binding_version: i64,
    pub max_seen_time: i64,
    pub serial: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub ver: i64,
    pub mode: String,
    pub lid: String,
    pub kid: String,
    pub product_id: String,
    pub prd: String,
    pub serial: String,
    pub revision: i64,
    pub binding_version: i64,
    pub device_key_hash: String,
    pub fingerprint_hash: String,
    pub fingerprint_version: u32,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub ent: Map<String, Value>,
    pub seat: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Valid,
    Expiring,
    Expired,
}

impl Status {
    pub fn allows_new_work(self) -> bool {
        matches!(self, Self::Valid | Self::Expiring)
    }
}

#[derive(Debug, Serialize)]
pub struct Verification {
    pub claims: Claims,
    pub status: Status,
    pub state: VerificationState,
}

pub fn sign_activation_challenge(
    challenge: &ActivationChallenge,
    expected: &ExpectedDevice<'_>,
    identity: &DeviceIdentity,
    now: i64,
) -> Result<String, Error> {
    validate_context(expected)?;
    valid_uuid(&challenge.challenge_id)?;
    decode_fixed::<32>(&challenge.nonce)?;
    let expires = chrono::DateTime::parse_from_rfc3339(&challenge.expires_at)
        .map_err(|_| Error::InvalidChallenge)?
        .timestamp();
    if now < 0 || now >= expires || expires.saturating_sub(now) > 300 {
        return Err(Error::InvalidChallenge);
    }
    let public = identity.public_key_base64();
    let message = activation_message(&ChallengeContext {
        challenge_id: &challenge.challenge_id,
        nonce: &challenge.nonce,
        product_id: expected.product_id,
        license_id: expected.license_id,
        device_public_key: &public,
        fingerprint_hash: expected.fingerprint_hash,
        fingerprint_version: expected.fingerprint_version,
    });
    if decode(&challenge.message)? != message.as_bytes() {
        return Err(Error::InvalidChallenge);
    }
    Ok(URL_SAFE_NO_PAD.encode(identity.0.sign(message.as_bytes()).to_bytes()))
}

pub fn accept_activation(
    response: &ActivationResponse,
    challenge: &ActivationChallenge,
    keys: &TrustedKeys,
    expected: &ExpectedDevice<'_>,
    identity: &DeviceIdentity,
    wall_now: i64,
) -> Result<Verification, Error> {
    let claims = verified_claims(&response.token, keys, expected, identity)?;
    let receipt = verified_object(&response.time_receipt, keys, "GMT-TIME")?;
    let same = receipt.get("ver").and_then(Value::as_i64) == Some(2)
        && receipt.get("operation").and_then(Value::as_str) == Some("activate")
        && receipt.get("challenge_id").and_then(Value::as_str)
            == Some(challenge.challenge_id.as_str())
        && receipt.get("nonce").and_then(Value::as_str) == Some(challenge.nonce.as_str())
        && receipt.get("product_id").and_then(Value::as_str) == Some(expected.product_id)
        && receipt.get("lid").and_then(Value::as_str) == Some(expected.license_id)
        && receipt.get("device_key_hash").and_then(Value::as_str)
            == Some(claims.device_key_hash.as_str())
        && receipt.get("serial").and_then(Value::as_str) == Some(claims.serial.as_str())
        && receipt.get("server_time").and_then(Value::as_i64) == Some(response.server_time)
        && response.revision == claims.revision
        && response.binding_version == claims.binding_version;
    if !same || response.server_time < claims.iat || response.server_time >= claims.exp {
        return Err(Error::InvalidChallenge);
    }
    // Bind the supplied challenge bytes to this device before accepting its time anchor.
    sign_activation_challenge(challenge, expected, identity, response.server_time)?;
    sign_activation_challenge(challenge, expected, identity, wall_now)?;
    let state = VerificationState {
        product_id: claims.product_id.clone(),
        license_id: claims.lid.clone(),
        device_key_hash: claims.device_key_hash.clone(),
        revision: claims.revision,
        binding_version: claims.binding_version,
        max_seen_time: response.server_time,
        serial: claims.serial.clone(),
    };
    verify(
        &response.token,
        keys,
        expected,
        identity,
        &state,
        wall_now,
        0,
    )
}

#[derive(Debug, Clone, Copy)]
pub struct SyncClock {
    pub wall_now: i64,
    pub monotonic_elapsed_seconds: u64,
}

fn sign_operation_challenge(
    operation: Operation,
    challenge: &DeviceChallenge,
    expected: &ExpectedDevice<'_>,
    identity: &DeviceIdentity,
    now: i64,
) -> Result<String, Error> {
    validate_context(expected)?;
    valid_uuid(&challenge.challenge_id)?;
    valid_uuid(&challenge.serial)?;
    decode_fixed::<32>(&challenge.nonce)?;
    let expires = chrono::DateTime::parse_from_rfc3339(&challenge.expires_at)
        .map_err(|_| Error::InvalidChallenge)?
        .timestamp();
    if now < 0 || now >= expires || expires.saturating_sub(now) > 300 {
        return Err(Error::InvalidChallenge);
    }
    let public = identity.public_key_base64();
    let message = operation_message(
        operation,
        &ChallengeContext {
            challenge_id: &challenge.challenge_id,
            nonce: &challenge.nonce,
            product_id: expected.product_id,
            license_id: expected.license_id,
            device_public_key: &public,
            fingerprint_hash: expected.fingerprint_hash,
            fingerprint_version: expected.fingerprint_version,
        },
        &challenge.serial,
    );
    if decode(&challenge.message)? != message.as_bytes() {
        return Err(Error::InvalidChallenge);
    }
    Ok(URL_SAFE_NO_PAD.encode(identity.0.sign(message.as_bytes()).to_bytes()))
}

pub fn sign_sync_challenge(
    challenge: &DeviceChallenge,
    expected: &ExpectedDevice<'_>,
    identity: &DeviceIdentity,
    now: i64,
) -> Result<String, Error> {
    sign_operation_challenge(Operation::Sync, challenge, expected, identity, now)
}

pub fn sign_acknowledgement(
    challenge: &DeviceChallenge,
    expected: &ExpectedDevice<'_>,
    identity: &DeviceIdentity,
    persisted: &VerificationState,
    now: i64,
) -> Result<String, Error> {
    if persisted.serial != challenge.serial
        || persisted.product_id != expected.product_id
        || persisted.license_id != expected.license_id
        || persisted.device_key_hash != identity.key_hash()
    {
        return Err(Error::InvalidChallenge);
    }
    sign_operation_challenge(Operation::Ack, challenge, expected, identity, now)
}

pub fn accept_sync(
    response: &ActivationResponse,
    challenge: &DeviceChallenge,
    keys: &TrustedKeys,
    expected: &ExpectedDevice<'_>,
    identity: &DeviceIdentity,
    state: &VerificationState,
    clock: SyncClock,
) -> Result<Verification, Error> {
    let claims = verified_claims(&response.token, keys, expected, identity)?;
    if state.product_id != expected.product_id
        || state.license_id != expected.license_id
        || state.device_key_hash != identity.key_hash()
    {
        return Err(Error::WrongDevice);
    }
    valid_uuid(&state.serial)?;
    if state.revision < 1
        || claims.revision < state.revision
        || claims.binding_version != state.binding_version
        || (claims.revision == state.revision && claims.serial != state.serial)
    {
        return Err(Error::Rollback);
    }
    let receipt = verified_object(&response.time_receipt, keys, "GMT-TIME")?;
    let same = receipt.get("ver").and_then(Value::as_i64) == Some(2)
        && receipt.get("operation").and_then(Value::as_str) == Some("sync")
        && receipt.get("challenge_id").and_then(Value::as_str)
            == Some(challenge.challenge_id.as_str())
        && receipt.get("nonce").and_then(Value::as_str) == Some(challenge.nonce.as_str())
        && receipt.get("product_id").and_then(Value::as_str) == Some(expected.product_id)
        && receipt.get("lid").and_then(Value::as_str) == Some(expected.license_id)
        && receipt.get("device_key_hash").and_then(Value::as_str)
            == Some(claims.device_key_hash.as_str())
        && receipt.get("serial").and_then(Value::as_str) == Some(claims.serial.as_str())
        && challenge.serial == claims.serial
        && receipt.get("server_time").and_then(Value::as_i64) == Some(response.server_time)
        && response.revision == claims.revision
        && response.binding_version == claims.binding_version;
    if !same || response.server_time < claims.iat || response.server_time >= claims.exp {
        return Err(Error::InvalidChallenge);
    }
    sign_sync_challenge(challenge, expected, identity, response.server_time)?;
    sign_sync_challenge(challenge, expected, identity, clock.wall_now)?;
    let elapsed =
        i64::try_from(clock.monotonic_elapsed_seconds).map_err(|_| Error::ClockSuspect)?;
    if !(0..=MAX_SAFE_INTEGER).contains(&state.max_seen_time) {
        return Err(Error::ClockSuspect);
    }
    let lower_bound = state
        .max_seen_time
        .checked_add(elapsed)
        .ok_or(Error::ClockSuspect)?;
    if lower_bound > MAX_SAFE_INTEGER
        || clock.wall_now.saturating_add(300) < lower_bound
        || response.server_time.saturating_add(300) < lower_bound
    {
        return Err(Error::ClockSuspect);
    }
    let anchored = VerificationState {
        max_seen_time: lower_bound.max(response.server_time),
        ..state.clone()
    };
    verify(
        &response.token,
        keys,
        expected,
        identity,
        &anchored,
        clock.wall_now,
        0,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineBundle {
    pub token: String,
    pub state: VerificationState,
}

pub fn save_demo_bundle(path: &std::path::Path, bundle: &OfflineBundle) -> std::io::Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec(bundle)?;
    let mut random = [0; 16];
    getrandom::getrandom(&mut random)
        .map_err(|_| std::io::Error::other("random source unavailable"))?;
    let temp = path.with_extension(format!("pending-{}", URL_SAFE_NO_PAD.encode(random)));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

pub fn verify(
    token: &str,
    keys: &TrustedKeys,
    expected: &ExpectedDevice<'_>,
    identity: &DeviceIdentity,
    state: &VerificationState,
    wall_now: i64,
    monotonic_elapsed_seconds: u64,
) -> Result<Verification, Error> {
    let claims = verified_claims(token, keys, expected, identity)?;
    if state.product_id != claims.product_id
        || state.license_id != claims.lid
        || state.device_key_hash != claims.device_key_hash
    {
        return Err(Error::WrongDevice);
    }
    valid_uuid(&state.serial)?;
    if state.revision < 1
        || state.binding_version < 1
        || claims.revision < state.revision
        || claims.binding_version != state.binding_version
        || (claims.revision == state.revision && claims.serial != state.serial)
    {
        return Err(Error::Rollback);
    }
    if state.max_seen_time < claims.iat
        || state.max_seen_time > MAX_SAFE_INTEGER
        || !(0..=MAX_SAFE_INTEGER).contains(&wall_now)
    {
        return Err(Error::ClockSuspect);
    }
    let elapsed = i64::try_from(monotonic_elapsed_seconds).map_err(|_| Error::ClockSuspect)?;
    let lower_bound = state
        .max_seen_time
        .checked_add(elapsed)
        .ok_or(Error::ClockSuspect)?;
    if lower_bound > MAX_SAFE_INTEGER {
        return Err(Error::ClockSuspect);
    }
    if wall_now.saturating_add(300) < lower_bound {
        return Err(Error::ClockSuspect);
    }
    let now = wall_now.max(lower_bound);
    if now < claims.nbf {
        return Err(Error::NotYetValid);
    }
    let status = if now >= claims.exp {
        Status::Expired
    } else if claims.exp - now <= 7 * 86_400 {
        Status::Expiring
    } else {
        Status::Valid
    };
    let next = VerificationState {
        product_id: claims.product_id.clone(),
        license_id: claims.lid.clone(),
        device_key_hash: claims.device_key_hash.clone(),
        revision: claims.revision,
        binding_version: claims.binding_version,
        max_seen_time: now,
        serial: claims.serial.clone(),
    };
    Ok(Verification {
        claims,
        status,
        state: next,
    })
}

fn verified_claims(
    token: &str,
    keys: &TrustedKeys,
    expected: &ExpectedDevice<'_>,
    identity: &DeviceIdentity,
) -> Result<Claims, Error> {
    validate_context(expected)?;
    let value = verified_object(token, keys, "GMT")?;
    let claims: Claims =
        serde_json::from_value(Value::Object(value)).map_err(|_| Error::Malformed)?;
    if claims.ver != 2
        || claims.mode != "offline_device"
        || claims.seat != 1
        || claims.fingerprint_version != 1
    {
        return Err(Error::Unsupported);
    }
    valid_uuid(&claims.product_id)?;
    valid_uuid(&claims.lid)?;
    valid_uuid(&claims.serial)?;
    if claims.product_id != expected.product_id {
        return Err(Error::WrongProduct);
    }
    if claims.lid != expected.license_id {
        return Err(Error::WrongLicense);
    }
    if claims.kid.is_empty()
        || claims.prd.is_empty()
        || claims.iat < 0
        || claims.nbf < claims.iat
        || claims.exp <= claims.nbf
        || claims.exp > MAX_SAFE_INTEGER
        || !(1..=MAX_SAFE_INTEGER).contains(&claims.revision)
        || !(1..=MAX_SAFE_INTEGER).contains(&claims.binding_version)
    {
        return Err(Error::Malformed);
    }
    decode_fixed::<32>(&claims.device_key_hash)?;
    decode_fixed::<32>(&claims.fingerprint_hash)?;
    if claims.device_key_hash != identity.key_hash() {
        return Err(Error::WrongDevice);
    }
    if claims.fingerprint_hash != expected.fingerprint_hash
        || claims.fingerprint_version != expected.fingerprint_version
    {
        return Err(Error::WrongFingerprint);
    }
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::WrongDevice)?;
    identity
        .0
        .verifying_key()
        .verify_strict(&nonce, &identity.0.sign(&nonce))
        .map_err(|_| Error::WrongDevice)?;
    Ok(claims)
}

fn validate_context(context: &ExpectedDevice<'_>) -> Result<(), Error> {
    valid_uuid(context.product_id)?;
    valid_uuid(context.license_id)?;
    decode_fixed::<32>(context.fingerprint_hash)?;
    if context.fingerprint_version != 1 {
        return Err(Error::Unsupported);
    }
    Ok(())
}
fn valid_uuid(value: &str) -> Result<(), Error> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| Error::Malformed)?;
    if id.to_string() != value {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn decode(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::Malformed)?;
    if bytes.is_empty() || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::Malformed);
    }
    Ok(bytes)
}
fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    decode(value)?.try_into().map_err(|_| Error::Malformed)
}
fn verified_object(
    token: &str,
    keys: &TrustedKeys,
    expected_type: &str,
) -> Result<Map<String, Value>, Error> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(Error::Malformed);
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Malformed);
    }
    let header = parse_strict_json(&decode(parts[0])?)?;
    let header = header.as_object().ok_or(Error::Malformed)?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA")
        || header.get("crv").and_then(Value::as_str) != Some("Ed25519")
        || header.get("typ").and_then(Value::as_str) != Some(expected_type)
    {
        return Err(Error::Unsupported);
    }
    let key_id = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(Error::Malformed)?;
    let public = keys.get(key_id).ok_or(Error::UnknownKey)?;
    let verifier = VerifyingKey::from_bytes(public).map_err(|_| Error::UnknownKey)?;
    let signature = Signature::from_bytes(&decode_fixed::<64>(parts[2])?);
    verifier
        .verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| Error::InvalidSignature)?;
    parse_strict_json(&decode(parts[1])?)?
        .as_object()
        .cloned()
        .ok_or(Error::Malformed)
}

pub fn parse_strict_json(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(Error::Malformed);
    }
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let StrictValue(value) = StrictValue::deserialize(&mut parser).map_err(|_| Error::Malformed)?;
    parser.end().map_err(|_| Error::Malformed)?;
    Ok(value)
}
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON without duplicate keys or non-integer numbers")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<StrictValue, E> {
                Ok(StrictValue(Value::Bool(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<StrictValue, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<StrictValue, E> {
                Ok(StrictValue(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<StrictValue, E> {
                Ok(StrictValue(Value::String(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<StrictValue, E> {
                Ok(StrictValue(Value::Number(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<StrictValue, E> {
                let number = i64::try_from(v).map_err(|_| E::custom("integer out of range"))?;
                Ok(StrictValue(Value::Number(number.into())))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StrictValue, A::Error> {
                let mut result = Vec::new();
                while let Some(StrictValue(v)) = seq.next_element()? {
                    result.push(v);
                }
                Ok(StrictValue(Value::Array(result)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StrictValue, A::Error> {
                let mut result = Map::new();
                while let Some((key, StrictValue(value))) =
                    map.next_entry::<String, StrictValue>()?
                {
                    if result.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(StrictValue(Value::Object(result)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}
