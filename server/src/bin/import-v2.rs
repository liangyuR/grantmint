use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, Row};
use std::{collections::HashMap, env, error::Error};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

fn field<T: DeserializeOwned>(value: &Value, name: &str) -> Result<T> {
    serde_json::from_value(value.get(name).ok_or("missing migration field")?.clone())
        .map_err(|_| "invalid migration field".into())
}

fn certificate(license: &Value, keys: &HashMap<String, (Uuid, Vec<u8>)>, slug: &str) -> Result<()> {
    let version: i64 = field(license, "binding_version")?;
    if version == 0 {
        if [
            "signed_token",
            "device_public_key",
            "signing_key_id",
            "certificate_serial",
            "fingerprint_hash",
            "fingerprint_version",
            "activated_at",
        ]
        .iter()
        .any(|name| !license[*name].is_null())
        {
            return Err("unbound license contains certificate or device".into());
        }
        return Ok(());
    }
    if version != 1 {
        return Err("unsupported binding version".into());
    }
    let token: String = field(license, "signed_token")?;
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 || token.len() > 131_072 {
        return Err("invalid source certificate".into());
    }
    let header = strict_json(&decode_segment(parts[0])?)?;
    let claims = strict_json(&decode_segment(parts[1])?)?;
    let key_id: String = field(license, "signing_key_id")?;
    let product: Uuid = field(license, "product_id")?;
    let (key_product, public) = keys.get(&key_id).ok_or("source signing key missing")?;
    if *key_product != product
        || header != json!({"alg":"EdDSA","crv":"Ed25519","typ":"GMT","kid":key_id})
    {
        return Err("certificate signing context mismatch".into());
    }
    let public: [u8; 32] = public.as_slice().try_into()?;
    let signature = Signature::from_slice(&decode_segment(parts[2])?)?;
    VerifyingKey::from_bytes(&public)?
        .verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)?;
    let device: String = field(license, "device_public_key")?;
    let decoded = STANDARD.decode(&device)?;
    if STANDARD.encode(&decoded) != device {
        return Err("noncanonical device key".into());
    }
    let device: [u8; 32] = decoded.as_slice().try_into()?;
    VerifyingKey::from_bytes(&device)?;
    let fingerprint: String = field(license, "fingerprint_hash")?;
    if decode_segment(&fingerprint)?.len() != 32 || license["fingerprint_version"] != 1 {
        return Err("invalid device fingerprint".into());
    }
    let iat: i64 = field(&claims, "iat")?;
    let nbf: i64 = field(&claims, "nbf")?;
    let exp: i64 = field(&claims, "exp")?;
    if iat < 0
        || nbf < iat
        || exp <= nbf
        || exp > grantmint_license_protocol::MAX_SAFE_INTEGER
        || claims["prd"] != slug
    {
        return Err("invalid certificate time or application".into());
    }
    let _: Uuid = field(license, "certificate_serial")?;
    let _: DateTime<Utc> = field(license, "activated_at")?;
    let expiry: DateTime<Utc> = field(license, "expires_at")?;
    for (claim, column) in [
        ("lid", "id"),
        ("kid", "key_id"),
        ("product_id", "product_id"),
        ("serial", "certificate_serial"),
        ("revision", "revision"),
        ("binding_version", "binding_version"),
        ("fingerprint_hash", "fingerprint_hash"),
        ("fingerprint_version", "fingerprint_version"),
        ("ent", "entitlements"),
    ] {
        if claims[claim] != license[column] {
            return Err("certificate/database metadata mismatch".into());
        }
    }
    if claims["ver"] != 2
        || claims["mode"] != "offline_device"
        || claims["seat"] != 1
        || claims["exp"] != expiry.timestamp()
        || claims["device_key_hash"] != grantmint_license_protocol::device_key_hash(&device)
    {
        return Err("source certificate is not a compatible device license".into());
    }
    Ok(())
}

fn decode_segment(value: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(value)?;
    if bytes.is_empty() || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err("noncanonical certificate encoding".into());
    }
    Ok(bytes)
}

fn strict_json(bytes: &[u8]) -> Result<Value> {
    struct Strict(Value);
    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Strict;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("unambiguous JSON")
                }
                fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                    Ok(Strict(Value::Bool(v)))
                }
                fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                    Ok(Strict(Value::Null))
                }
                fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                    Ok(Strict(Value::String(v.into())))
                }
                fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                    if !(-grantmint_license_protocol::MAX_SAFE_INTEGER
                        ..=grantmint_license_protocol::MAX_SAFE_INTEGER)
                        .contains(&v)
                    {
                        return Err(E::custom("unsafe integer"));
                    }
                    Ok(Strict(Value::Number(v.into())))
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                    self.visit_i64(i64::try_from(v).map_err(|_| E::custom("unsafe integer"))?)
                }
                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> std::result::Result<Strict, A::Error> {
                    let mut a = Vec::new();
                    while let Some(Strict(v)) = seq.next_element()? {
                        a.push(v);
                    }
                    Ok(Strict(Value::Array(a)))
                }
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> std::result::Result<Strict, A::Error> {
                    let mut m = serde_json::Map::new();
                    while let Some((k, Strict(v))) = map.next_entry::<String, Strict>()? {
                        if m.insert(k, v).is_some() {
                            return Err(de::Error::custom("duplicate key"));
                        }
                    }
                    Ok(Strict(Value::Object(m)))
                }
            }
            d.deserialize_any(V)
        }
    }
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let Strict(value) = Strict::deserialize(&mut parser)?;
    parser.end()?;
    Ok(value)
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        if error.is::<sqlx::Error>() || error.is::<serde_json::Error>() {
            eprintln!("Migration refused: database or JSON operation failed (sensitive details suppressed)");
        } else {
            eprintln!("Migration refused: {error}");
        }
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args
        .iter()
        .any(|v| !matches!(v.as_str(), "--apply" | "--writes-frozen"))
    {
        return Err("usage: import-v2 [--apply --writes-frozen]; connection URLs must be environment variables".into());
    }
    let apply = args.iter().any(|v| v == "--apply");
    if apply && !args.iter().any(|v| v == "--writes-frozen") {
        return Err("freeze source and destination writes before --apply".into());
    }
    let source_url = env::var("SOURCE_DATABASE_URL").map_err(|_| "missing SOURCE_DATABASE_URL")?;
    let target_url = env::var("DATABASE_URL").map_err(|_| "missing DATABASE_URL")?;
    if source_url == target_url {
        return Err("source and target must be different databases".into());
    }
    let product: Option<Uuid> = env::var("IMPORT_PRODUCT_ID")
        .ok()
        .map(|v| v.parse())
        .transpose()?;
    let source = PgPoolOptions::new()
        .max_connections(1)
        .connect(&source_url)
        .await?;
    let target = PgPoolOptions::new()
        .max_connections(1)
        .connect(&target_url)
        .await?;
    let mut snapshot = source.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *snapshot)
        .await?;
    let source_marker: bool = sqlx::query_scalar("SELECT to_regclass('public.flyway_schema_history') IS NOT NULL AND to_regclass('public.offline_activation_challenges') IS NOT NULL").fetch_one(&mut *snapshot).await?;
    let target_marker: bool = sqlx::query_scalar("SELECT to_regclass('public.flyway_schema_history') IS NULL AND to_regclass('public._sqlx_migrations') IS NOT NULL").fetch_one(&target).await?;
    if !source_marker || !target_marker {
        return Err("source must be Java v2 and target a separately migrated Rust database".into());
    }
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM offline_activation_challenges c JOIN licenses l ON l.id=c.license_id WHERE ($1::uuid IS NULL OR l.product_id=$1) AND (c.expires_at > now() OR c.consumed_at >= now()-interval '24 hours')")
        .bind(product).fetch_one(&mut *snapshot).await?;
    if pending != 0 {
        return Err("source has live challenges or retained idempotent responses; wait for retention to expire".into());
    }
    let applications: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(p) FROM products p WHERE ($1::uuid IS NULL OR p.id=$1) ORDER BY p.id",
    )
    .bind(product)
    .fetch_all(&mut *snapshot)
    .await?;
    if applications.is_empty() {
        return Err("no applications selected".into());
    }
    let key_rows = sqlx::query("SELECT key_id,product_id,public_key,created_at,status,algorithm,retired_at FROM signing_keys WHERE ($1::uuid IS NULL OR product_id=$1)")
        .bind(product).fetch_all(&mut *snapshot).await?;
    let mut keys = HashMap::new();
    for row in &key_rows {
        keys.insert(
            row.try_get::<String, _>("key_id")?,
            (
                row.try_get::<Uuid, _>("product_id")?,
                row.try_get::<Vec<u8>, _>("public_key")?,
            ),
        );
    }
    for row in &key_rows {
        let public: [u8; 32] = row
            .try_get::<Vec<u8>, _>("public_key")?
            .as_slice()
            .try_into()?;
        VerifyingKey::from_bytes(&public)?;
        if row.try_get::<String, _>("algorithm")? != "Ed25519" {
            return Err("unsupported key algorithm".into());
        }
    }
    let mut slugs = HashMap::new();
    for app in &applications {
        let app_id: Uuid = field(app, "id")?;
        slugs.insert(app_id, field::<String>(app, "slug")?);
        let key: String = field(app, "active_signing_key_id")?;
        if keys.get(&key).map(|k| k.0) != Some(app_id) {
            return Err(
                "application current signing key missing or belongs to another application".into(),
            );
        }
        let current = key_rows
            .iter()
            .find(|row| row.get::<String, _>("key_id") == key)
            .ok_or("current signing key missing")?;
        if current.try_get::<String, _>("status")? == "retired"
            || current
                .try_get::<Option<DateTime<Utc>>, _>("retired_at")?
                .is_some()
        {
            return Err("application current signing key is retired".into());
        }
    }
    let licenses: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(l) FROM licenses l WHERE ($1::uuid IS NULL OR l.product_id=$1) ORDER BY l.id")
        .bind(product).fetch_all(&mut *snapshot).await?;
    let snapshot_now: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut *snapshot)
        .await?;
    for license in &licenses {
        let status: String = field(license, "status")?;
        if license["mode"] != "offline_device_v2"
            || !matches!(
                status.as_str(),
                "created" | "active" | "expired" | "revoked"
            )
        {
            return Err(
                "v1, suspended or unsupported licenses require explicit handling before migration"
                    .into(),
            );
        }
        if status == "revoked" && license["revoked_at"].is_null() {
            return Err("revoked license has no revocation timestamp".into());
        }
        let hash: String = field(license, "activation_secret_hash")?;
        if hash.len() != 64 || !hash.bytes().all(|v| v.is_ascii_hexdigit()) {
            return Err("invalid activation secret hash".into());
        }
        let expiry: DateTime<Utc> = field(license, "expires_at")?;
        if status == "expired" && expiry > snapshot_now {
            return Err("explicitly expired future contract requires manual handling".into());
        }
        let revision: i64 = field(license, "revision")?;
        if !(1..=grantmint_license_protocol::MAX_SAFE_INTEGER).contains(&revision)
            || license["max_seats"] != 1
            || !license["entitlements"].is_object()
        {
            return Err("invalid source contract".into());
        }
        grantmint_license_protocol::canonical_json(&license["entitlements"])?;
        if expiry.timestamp() < 0
            || expiry.timestamp() > grantmint_license_protocol::MAX_SAFE_INTEGER
        {
            return Err("invalid contract expiry".into());
        }
        if license["holder_name"].as_str().is_none() || license["holder_email"].as_str().is_none() {
            return Err("missing customer snapshot".into());
        }
        let application: Uuid = field(license, "product_id")?;
        certificate(
            license,
            &keys,
            slugs
                .get(&application)
                .ok_or("license application missing")?,
        )?;
    }
    let audits: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(a) FROM audit_log a WHERE (a.target_type='product' AND a.target_id IN (SELECT id::text FROM products WHERE ($1::uuid IS NULL OR id=$1))) OR (a.target_type='license' AND a.target_id IN (SELECT id::text FROM licenses WHERE ($1::uuid IS NULL OR product_id=$1))) ORDER BY a.occurred_at,a.id")
        .bind(product).fetch_all(&mut *snapshot).await?;
    let mut tx = target.begin().await?;
    sqlx::query("LOCK TABLE applications,signing_keys,licenses,device_bindings,certificates,challenges,renewals,audit_events IN ACCESS EXCLUSIVE MODE").execute(&mut *tx).await?;
    let occupied: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications) OR EXISTS(SELECT 1 FROM signing_keys) OR EXISTS(SELECT 1 FROM licenses) OR EXISTS(SELECT 1 FROM device_bindings) OR EXISTS(SELECT 1 FROM certificates) OR EXISTS(SELECT 1 FROM challenges) OR EXISTS(SELECT 1 FROM renewals) OR EXISTS(SELECT 1 FROM audit_events)").fetch_one(&mut *tx).await?;
    if occupied {
        return Err(
            "target business database must be empty; merge/import overwrite is forbidden".into(),
        );
    }
    if !apply {
        tx.rollback().await?;
        snapshot.rollback().await?;
        println!("CHECK PASSED: {} applications, {} keys, {} licenses, {} audit records; no writes performed",applications.len(),keys.len(),licenses.len(),audits.len());
        return Ok(());
    }
    for app in &applications {
        sqlx::query("INSERT INTO applications(id,slug,name,description,signing_key_id,created_at) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(field::<Uuid>(app,"id")?).bind(field::<String>(app,"slug")?).bind(field::<String>(app,"name")?)
            .bind(app["description"].as_str().unwrap_or("")).bind(field::<String>(app,"active_signing_key_id")?).bind(field::<DateTime<Utc>>(app,"created_at")?)
            .execute(&mut *tx).await?;
    }
    for row in &key_rows {
        sqlx::query("INSERT INTO signing_keys(key_id,application_id,public_key,created_at) VALUES($1,$2,$3,$4)")
            .bind(row.try_get::<String,_>("key_id")?).bind(row.try_get::<Uuid,_>("product_id")?).bind(STANDARD.encode(row.try_get::<Vec<u8>,_>("public_key")?))
            .bind(row.try_get::<DateTime<Utc>,_>("created_at")?).execute(&mut *tx).await?;
    }
    let mut license_apps = HashMap::new();
    for l in &licenses {
        let id: Uuid = field(l, "id")?;
        let app: Uuid = field(l, "product_id")?;
        license_apps.insert(id, app);
        sqlx::query("INSERT INTO licenses(id,application_id,key_id,customer,expires_at,entitlements,activation_secret_hash,revision,revoked_at,revoke_reason,created_at) VALUES($1,$2,$3,$4,$5,$6,decode($7,'hex'),$8,$9,$10,$11)")
            .bind(id).bind(app).bind(field::<String>(l,"key_id")?).bind(json!({"name":l["holder_name"],"email":l["holder_email"]}))
            .bind(field::<DateTime<Utc>>(l,"expires_at")?).bind(&l["entitlements"]).bind(field::<String>(l,"activation_secret_hash")?).bind(field::<i64>(l,"revision")?)
            .bind(field::<Option<DateTime<Utc>>>(l,"revoked_at")?).bind(field::<Option<String>>(l,"revocation_reason")?).bind(field::<DateTime<Utc>>(l,"issued_at")?)
            .execute(&mut *tx).await?;
        if field::<i64>(l, "binding_version")? == 1 {
            sqlx::query("INSERT INTO device_bindings(license_id,device_public_key,fingerprint_hash,fingerprint_version,binding_version,bound_at) VALUES($1,$2,$3,$4,1,$5)")
                .bind(id).bind(field::<String>(l,"device_public_key")?).bind(field::<String>(l,"fingerprint_hash")?).bind(field::<i32>(l,"fingerprint_version")?)
                .bind(field::<DateTime<Utc>>(l,"activated_at")?).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO certificates(license_id,revision,binding_version,serial,key_id,token,reason,issued_at) VALUES($1,$2,1,$3,$4,$5,'migration',$6)")
                .bind(id).bind(field::<i64>(l,"revision")?).bind(field::<Uuid>(l,"certificate_serial")?).bind(field::<String>(l,"signing_key_id")?)
                .bind(field::<String>(l,"signed_token")?).bind(field::<DateTime<Utc>>(l,"activated_at")?).execute(&mut *tx).await?;
        }
    }
    for audit in &audits {
        let target_id: Uuid = field::<String>(audit, "target_id")?.parse()?;
        let (app, license) = if audit["target_type"] == "license" {
            (license_apps.get(&target_id).copied(), Some(target_id))
        } else {
            (Some(target_id), None)
        };
        sqlx::query("INSERT INTO audit_events(actor,application_id,license_id,action,detail,created_at) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(field::<String>(audit,"actor")?).bind(app).bind(license).bind(field::<String>(audit,"action")?)
            .bind(json!({"legacyId":audit["id"],"legacyActorType":audit["actor_type"],"original":audit["detail"]}))
            .bind(field::<DateTime<Utc>>(audit,"occurred_at")?).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO audit_events(actor,action,detail) VALUES('migration','migration.imported',$1)")
        .bind(json!({"applications":applications.len(),"licenses":licenses.len(),"keys":keys.len(),"auditRecords":audits.len()})).execute(&mut *tx).await?;
    tx.commit().await?;
    snapshot.rollback().await?;
    println!("IMPORTED: {} applications and {} licenses; certificate bytes, identities and revocations preserved",applications.len(),licenses.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn source_certificate_requires_matching_metadata_and_unambiguous_signed_claims() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../grantmint-core/src/test/resources/offline-device-v2.json"
        ))
        .unwrap();
        let c = &fixture["claims"];
        let mut license = json!({
            "binding_version":1,"signed_token":fixture["token"],"device_public_key":fixture["devicePublicKey"],
            "signing_key_id":"fixture-signing-key","product_id":c["product_id"],"id":c["lid"],"key_id":c["kid"],
            "certificate_serial":c["serial"],"revision":c["revision"],"fingerprint_hash":c["fingerprint_hash"],
            "fingerprint_version":1,"entitlements":c["ent"],
            "expires_at":DateTime::from_timestamp(c["exp"].as_i64().unwrap(),0).unwrap(),
            "activated_at":DateTime::from_timestamp(c["iat"].as_i64().unwrap(),0).unwrap(),
        });
        let keys = HashMap::from([(
            "fixture-signing-key".into(),
            (
                field::<Uuid>(c, "product_id").unwrap(),
                STANDARD
                    .decode(fixture["serverPublicKey"].as_str().unwrap())
                    .unwrap(),
            ),
        )]);
        let slug = c["prd"].as_str().unwrap();
        certificate(&license, &keys, slug).unwrap();
        license["fingerprint_hash"] = json!(URL_SAFE_NO_PAD.encode([99; 32]));
        assert!(certificate(&license, &keys, slug).is_err());
        license["fingerprint_hash"] = c["fingerprint_hash"].clone();
        let raw = c.to_string();
        let duplicate = format!("{{\"revision\":0,{}", &raw[1..]);
        let seed_hex = fixture["serverSeedHex"].as_str().unwrap();
        let seed: Vec<u8> = (0..seed_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&seed_hex[i..i + 2], 16).unwrap())
            .collect();
        let signing = SigningKey::from_bytes(&seed.try_into().unwrap());
        let header = fixture["token"]
            .as_str()
            .unwrap()
            .split('.')
            .next()
            .unwrap();
        let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(duplicate));
        license["signed_token"] = json!(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signing.sign(input.as_bytes()).to_bytes())
        ));
        assert!(certificate(&license, &keys, slug).is_err());
    }
}
