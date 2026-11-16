use base64::{engine::general_purpose::STANDARD, Engine};
use grantmint_offline::{
    accept_activation, parse_strict_json, sign_activation_challenge, verify, ActivationChallenge,
    ActivationResponse, DeviceIdentity, ExpectedDevice, TrustedKeys, VerificationState,
};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(parse_strict_json(&fs::read(
        path,
    )?)?)?)
}
fn private_create(path: &Path) -> std::io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
fn identity(path: &str) -> Result<DeviceIdentity, Box<dyn std::error::Error>> {
    let seed: [u8; 32] = fs::read(path)?
        .try_into()
        .map_err(|_| "device seed must be exactly 32 raw bytes")?;
    Ok(DeviceIdentity::from_seed(seed))
}
fn keys(path: &str) -> Result<TrustedKeys, Box<dyn std::error::Error>> {
    let encoded: std::collections::BTreeMap<String, String> = read_json(path)?;
    encoded
        .into_iter()
        .map(|(id, key)| {
            let public: [u8; 32] = STANDARD
                .decode(key)?
                .try_into()
                .map_err(|_| "public key must be 32 bytes")?;
            Ok((id, public))
        })
        .collect()
}
fn persist(
    path: &str,
    state: &VerificationState,
    initial: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec_pretty(state)?;
    if initial {
        let mut file = private_create(Path::new(path))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    } else {
        let temp = format!("{path}.pending-{}", std::process::id());
        let mut file = private_create(Path::new(&temp))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
    }
    Ok(())
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    if args.first().map(String::as_str) == Some("keygen-demo") && args.len() == 2 {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| "random source unavailable")?;
        let device = DeviceIdentity::from_seed(seed);
        let mut file = private_create(Path::new(&args[1]))?;
        file.write_all(&seed)?;
        file.sync_all()?;
        println!(
            "{}",
            serde_json::json!({"devicePublicKey":device.public_key_base64(),"deviceKeyHash":device.key_hash()})
        );
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("sign-challenge") && args.len() == 6 {
        let device = identity(&args[1])?;
        let challenge: ActivationChallenge = read_json(&args[2])?;
        let expected = ExpectedDevice {
            product_id: &args[3],
            license_id: &args[4],
            fingerprint_hash: &args[5],
            fingerprint_version: 1,
        };
        let signature = sign_activation_challenge(&challenge, &expected, &device, now)?;
        println!(
            "{}",
            serde_json::json!({"challengeId":challenge.challenge_id,"signature":signature})
        );
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("accept-activation") && args.len() == 9 {
        let device = identity(&args[1])?;
        let response: ActivationResponse = read_json(&args[2])?;
        let challenge: ActivationChallenge = read_json(&args[3])?;
        let trusted = keys(&args[4])?;
        let expected = ExpectedDevice {
            product_id: &args[5],
            license_id: &args[6],
            fingerprint_hash: &args[7],
            fingerprint_version: 1,
        };
        if Path::new(&args[8]).exists() {
            return Err(
                "activation state already exists; refusing to reset high-water marks".into(),
            );
        }
        let result = accept_activation(&response, &challenge, &trusted, &expected, &device, now)?;
        persist(&args[8], &result.state, true)?;
        println!(
            "{}",
            serde_json::json!({"status":result.status,"serial":result.claims.serial,"expiresAt":result.claims.exp})
        );
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("verify") && args.len() == 8 {
        let device = identity(&args[1])?;
        let token = fs::read_to_string(&args[2])?;
        let trusted = keys(&args[3])?;
        let expected = ExpectedDevice {
            product_id: &args[4],
            license_id: &args[5],
            fingerprint_hash: &args[6],
            fingerprint_version: 1,
        };
        let state: VerificationState = read_json(&args[7])?;
        let result = verify(token.trim(), &trusted, &expected, &device, &state, now, 0)?;
        persist(&args[7], &result.state, false)?;
        println!(
            "{}",
            serde_json::json!({"status":result.status,"serial":result.claims.serial,"expiresAt":result.claims.exp})
        );
        if result.status == grantmint_offline::Status::Expired {
            std::process::exit(3);
        }
        return Ok(());
    }
    Err("usage: keygen-demo SEED | sign-challenge SEED CHALLENGE PRODUCT LICENSE FINGERPRINT | accept-activation SEED RESPONSE CHALLENGE KEYS PRODUCT LICENSE FINGERPRINT STATE | verify SEED TOKEN KEYS PRODUCT LICENSE FINGERPRINT STATE".into())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Verification failed: {error}");
        std::process::exit(1);
    }
}
