use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

pub struct ChallengeContext<'a> {
    pub challenge_id: &'a str,
    pub nonce: &'a str,
    pub product_id: &'a str,
    pub license_id: &'a str,
    pub device_public_key: &'a str,
    pub fingerprint_hash: &'a str,
    pub fingerprint_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Sync,
    Ack,
}
impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Ack => "ack",
        }
    }
}

fn message(domain: &str, c: &ChallengeContext<'_>) -> String {
    format!(
        "grantmint.{domain}.v2\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        c.challenge_id,
        c.nonce,
        c.product_id,
        c.license_id,
        c.device_public_key,
        c.fingerprint_hash,
        c.fingerprint_version
    )
}
pub fn activation_message(c: &ChallengeContext<'_>) -> String {
    message("activate", c)
}
pub fn operation_message(operation: Operation, c: &ChallengeContext<'_>, serial: &str) -> String {
    format!("{}\n{serial}", message(operation.as_str(), c))
}
pub fn device_key_hash(public: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationChallenge {
    pub challenge_id: String,
    pub nonce: String,
    pub message: String,
    pub expires_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceChallenge {
    pub challenge_id: String,
    pub nonce: String,
    pub message: String,
    pub expires_at: String,
    pub serial: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    pub token: String,
    pub revision: i64,
    pub binding_version: i64,
    pub server_time: i64,
    pub time_receipt: String,
}

pub fn canonical_json(value: &Value) -> Result<String, &'static str> {
    fn encode(v: &Value, depth: usize) -> Result<String, &'static str> {
        if depth > 64 {
            return Err("JSON too deep");
        }
        match v {
            Value::Number(n) => match n.as_i64() {
                Some(i) if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) => Ok(i.to_string()),
                _ => Err("unsafe number"),
            },
            Value::Array(a) => Ok(format!(
                "[{}]",
                a.iter()
                    .map(|v| encode(v, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(",")
            )),
            Value::Object(m) => {
                let mut keys: Vec<_> = m.keys().collect();
                keys.sort();
                let mut fields = Vec::new();
                for k in keys {
                    fields.push(format!(
                        "{}:{}",
                        serde_json::to_string(k).map_err(|_| "JSON")?,
                        encode(&m[k], depth + 1)?
                    ));
                }
                Ok(format!("{{{}}}", fields.join(",")))
            }
            _ => serde_json::to_string(v).map_err(|_| "JSON"),
        }
    }
    let result = encode(value, 0)?;
    if result.len() > 90_000 {
        return Err("JSON too large");
    }
    Ok(result)
}
pub fn sign_token(
    key: &SigningKey,
    key_id: &str,
    typ: &str,
    payload: &Value,
) -> Result<String, &'static str> {
    if key_id.is_empty() || !matches!(typ, "GMT" | "GMT-TIME") {
        return Err("invalid signing context");
    }
    let header = serde_json::json!({"alg":"EdDSA","crv":"Ed25519","kid":key_id,"typ":typ});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(canonical_json(&header)?),
        URL_SAFE_NO_PAD.encode(canonical_json(payload)?)
    );
    let signature = key.sign(input.as_bytes());
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}
