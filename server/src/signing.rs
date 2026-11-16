use crate::error::{Error, Result};
use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyConfig {
    pub key_id: String,
    pub public_key: String,
    pub private_key_file: String,
}
#[derive(Clone)]
pub struct Keys {
    pub root: PathBuf,
    pub entries: HashMap<String, KeyConfig>,
}
impl Keys {
    pub fn load(
        root: PathBuf,
        file: &Path,
    ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let configs: Vec<KeyConfig> = serde_json::from_slice(&std::fs::read(file)?)?;
        let mut entries = HashMap::new();
        for c in configs {
            if c.key_id.is_empty()
                || c.key_id.len() > 128
                || entries.insert(c.key_id.clone(), c).is_some()
            {
                return Err("invalid or duplicate key ID".into());
            }
        }
        let keys = Self {
            root: root.canonicalize()?,
            entries,
        };
        for id in keys.entries.keys() {
            keys.signer(id)
                .map_err(|e| format!("invalid signing key {id}: {}", e.1))?;
        }
        Ok(keys)
    }
    pub fn signer(&self, id: &str) -> Result<SigningKey> {
        self.read_signer(id)
            .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "signing_key_unavailable"))
    }
    fn read_signer(&self, id: &str) -> std::result::Result<SigningKey, Box<dyn std::error::Error>> {
        let c = self.entries.get(id).ok_or("missing key")?;
        let relative = Path::new(&c.private_key_file);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err("invalid key path".into());
        }
        let path = self.root.join(relative);
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink()
            || !path.canonicalize()?.starts_with(&self.root)
        {
            return Err("unsafe key path".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(&path)?.permissions().mode() & 0o077 != 0 {
                return Err("key permissions must be owner-only".into());
            }
        }
        let bytes = std::fs::read(path)?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "key must contain exactly 32 raw bytes")?;
        let signer = SigningKey::from_bytes(&seed);
        if STANDARD.encode(signer.verifying_key().as_bytes()) != c.public_key {
            return Err("public key mismatch".into());
        }
        Ok(signer)
    }
}

pub fn keygen(
    root: &Path,
    key_id: &str,
    file: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use rand::RngCore;
    use std::io::Write;
    let root = root.canonicalize()?;
    let relative = Path::new(file);
    if key_id.is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|x| !matches!(x, std::path::Component::Normal(_)))
    {
        return Err("invalid key ID or path".into());
    }
    let path = root.join(relative);
    if !path
        .parent()
        .ok_or("missing parent")?
        .canonicalize()?
        .starts_with(&root)
    {
        return Err("unsafe key path".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(path)?;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    output.write_all(&seed)?;
    output.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"keyId":key_id,"publicKey":STANDARD.encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes()),"privateKeyFile":file})
    );
    Ok(())
}
