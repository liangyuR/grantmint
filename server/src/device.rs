use crate::json::StrictJson;
use crate::{
    audit,
    error::{bad, conflict, field, unauthorized, uuid, Error, Result},
    hash, AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use grantmint_license_protocol::{
    activation_message, device_key_hash, operation_message, sign_token, ChallengeContext, Operation,
};
use rand::RngCore;
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub async fn locked(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    app: Option<Uuid>,
) -> Result<PgRow> {
    sqlx::query("SELECT l.*,a.slug,a.signing_key_id,a.archived_at FROM licenses l JOIN applications a ON a.id=l.application_id WHERE l.id=$1 AND ($2::uuid IS NULL OR l.application_id=$2) FOR UPDATE OF l").bind(id).bind(app).fetch_optional(&mut **tx).await?.ok_or(unauthorized())
}
fn usable(l: &PgRow, check_expiry: bool) -> Result<()> {
    if l.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some() {
        return Err(Error(StatusCode::UNPROCESSABLE_ENTITY, "license_revoked"));
    }
    if check_expiry && l.get::<DateTime<Utc>, _>("expires_at") <= Utc::now() {
        return Err(Error(StatusCode::UNPROCESSABLE_ENTITY, "license_expired"));
    }
    Ok(())
}
fn decode<const N: usize>(s: &str, standard: bool) -> Result<[u8; N]> {
    let engine = if standard {
        &STANDARD
    } else {
        &URL_SAFE_NO_PAD
    };
    let bytes = engine
        .decode(s)
        .map_err(|_| bad("invalid_device_encoding"))?;
    if engine.encode(&bytes) != s {
        return Err(bad("invalid_device_encoding"));
    }
    bytes.try_into().map_err(|_| bad("invalid_device_encoding"))
}
fn device(v: &Value) -> Result<(&str, &str, i32)> {
    let key = field(v, "devicePublicKey")?;
    let fingerprint = field(v, "fingerprintHash")?;
    let bytes = decode::<32>(key, true)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| bad("invalid_device_key"))?;
    decode::<32>(fingerprint, false)?;
    if v["fingerprintVersion"].as_i64() != Some(1) {
        return Err(bad("unsupported_fingerprint_version"));
    }
    Ok((key, fingerprint, 1))
}
pub fn idempotency(v: &Value) -> Result<&str> {
    let key = field(v, "idempotencyKey")?;
    if !(16..=128).contains(&key.len())
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(bad("invalid_idempotency_key"));
    }
    Ok(key)
}
async fn binding(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    key: &str,
    fingerprint: &str,
) -> Result<Option<PgRow>> {
    let b = sqlx::query("SELECT * FROM device_bindings WHERE license_id=$1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    if let Some(ref b) = b {
        if b.get::<String, _>("device_public_key") != key
            || b.get::<String, _>("fingerprint_hash") != fingerprint
            || b.get::<i32, _>("fingerprint_version") != 1
        {
            return Err(conflict("device_already_bound"));
        }
    }
    Ok(b)
}
async fn current_serial(tx: &mut Transaction<'_, Postgres>, l: &PgRow) -> Result<Uuid> {
    sqlx::query_scalar(
        "SELECT serial FROM certificates WHERE license_id=$1 AND revision=$2 AND binding_version=1",
    )
    .bind(l.get::<Uuid, _>("id"))
    .bind(l.get::<i64, _>("revision"))
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(conflict("not_activated"))
}
fn message(ch: &PgRow, app: Uuid, license: Uuid) -> String {
    let challenge_id = ch.get::<Uuid, _>("id").to_string();
    let product_id = app.to_string();
    let license_id = license.to_string();
    let nonce: String = ch.get("nonce");
    let key: String = ch.get("device_public_key");
    let fp: String = ch.get("fingerprint_hash");
    let context = ChallengeContext {
        challenge_id: &challenge_id,
        nonce: &nonce,
        product_id: &product_id,
        license_id: &license_id,
        device_public_key: &key,
        fingerprint_hash: &fp,
        fingerprint_version: 1,
    };
    match ch.get::<String, _>("operation").as_str() {
        "activate" => activation_message(&context),
        op => operation_message(
            if op == "sync" {
                Operation::Sync
            } else {
                Operation::Ack
            },
            &context,
            &ch.get::<Uuid, _>("serial").to_string(),
        ),
    }
}
pub async fn challenge(
    State(s): State<AppState>,
    StrictJson(v): StrictJson,
) -> Result<Json<Value>> {
    make_challenge(s, v, "activate").await
}
pub async fn sync_challenge(
    State(s): State<AppState>,
    StrictJson(v): StrictJson,
) -> Result<Json<Value>> {
    let op = field(&v, "operation")?.to_owned();
    if op != "sync" && op != "ack" {
        return Err(bad("invalid_operation"));
    }
    make_challenge(s, v, &op).await
}
async fn make_challenge(s: AppState, v: Value, operation: &str) -> Result<Json<Value>> {
    let app = uuid(&v, "productId")?;
    let license = uuid(&v, "licenseId")?;
    let (key, fp, _) = device(&v)?;
    let mut tx = s.pool.begin().await?;
    let l = locked(&mut tx, license, Some(app)).await?;
    if operation == "activate" {
        let secret = v["activationSecret"]
            .as_str()
            .filter(|s| s.len() == 64)
            .ok_or(unauthorized())?;
        if !bool::from(hash(secret).ct_eq(&l.get::<Vec<u8>, _>("activation_secret_hash"))) {
            return Err(unauthorized());
        }
    }
    usable(&l, operation == "activate")?;
    let bound = binding(&mut tx, license, key, fp).await?;
    let serial = if operation == "activate" {
        None
    } else {
        if bound.is_none() {
            return Err(unauthorized());
        }
        let current = current_serial(&mut tx, &l).await?;
        if operation == "ack" && uuid(&v, "serial")? != current {
            return Err(conflict("certificate_changed"));
        }
        if operation == "sync" && v.get("serial").is_some() && uuid(&v, "serial")? != current {
            return Err(conflict("certificate_changed"));
        }
        Some(current)
    };
    sqlx::query("DELETE FROM challenges WHERE license_id=$1 AND expires_at<now() AND (response IS NULL OR consumed_at<now()-interval '24 hours')").bind(license).execute(&mut *tx).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM challenges WHERE license_id=$1")
        .bind(license)
        .fetch_one(&mut *tx)
        .await?;
    if count >= 64 {
        return Err(Error(StatusCode::TOO_MANY_REQUESTS, "challenge_limit"));
    }
    let id = Uuid::new_v4();
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce = URL_SAFE_NO_PAD.encode(nonce);
    let expires = Utc::now() + Duration::minutes(5);
    let ch=sqlx::query("INSERT INTO challenges(id,license_id,operation,nonce,device_public_key,fingerprint_hash,fingerprint_version,serial,expires_at) VALUES($1,$2,$3,$4,$5,$6,1,$7,$8) RETURNING *").bind(id).bind(license).bind(operation).bind(&nonce).bind(key).bind(fp).bind(serial).bind(expires).fetch_one(&mut *tx).await?;
    let mut response = json!({"challengeId":id,"nonce":nonce,"message":URL_SAFE_NO_PAD.encode(message(&ch,app,license)),"expiresAt":expires});
    if let Some(serial) = serial {
        response["serial"] = json!(serial)
    }
    tx.commit().await?;
    Ok(Json(response))
}
pub async fn issue_certificate(
    s: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    l: &PgRow,
    reason: &str,
) -> Result<Option<Uuid>> {
    let id: Uuid = l.get("id");
    let revision: i64 = l.get("revision");
    if let Some(serial) = sqlx::query_scalar(
        "SELECT serial FROM certificates WHERE license_id=$1 AND revision=$2 AND binding_version=1",
    )
    .bind(id)
    .bind(revision)
    .fetch_optional(&mut **tx)
    .await?
    {
        return Ok(Some(serial));
    }
    let Some(b) = sqlx::query("SELECT * FROM device_bindings WHERE license_id=$1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };
    let key_id: String = l.get("signing_key_id");
    let signer = s.keys.signer(&key_id)?;
    let public: String = sqlx::query_scalar(
        "SELECT public_key FROM signing_keys WHERE key_id=$1 AND application_id=$2",
    )
    .bind(&key_id)
    .bind(l.get::<Uuid, _>("application_id"))
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(conflict("signing_key_conflict"))?;
    if public != STANDARD.encode(signer.verifying_key().as_bytes()) {
        return Err(conflict("signing_key_conflict"));
    }
    let now = Utc::now().timestamp();
    let exp = l.get::<DateTime<Utc>, _>("expires_at").timestamp();
    if now >= exp {
        return Err(Error(StatusCode::UNPROCESSABLE_ENTITY, "license_expired"));
    }
    let serial = Uuid::new_v4();
    let pubkey = decode::<32>(&b.get::<String, _>("device_public_key"), true)?;
    let payload = json!({"ver":2,"mode":"offline_device","lid":id,"kid":l.get::<String,_>("key_id"),"product_id":l.get::<Uuid,_>("application_id"),"prd":l.get::<String,_>("slug"),"serial":serial,"revision":revision,"binding_version":1,"device_key_hash":device_key_hash(&pubkey),"fingerprint_hash":b.get::<String,_>("fingerprint_hash"),"fingerprint_version":1,"iat":now,"nbf":now,"exp":exp,"ent":l.get::<Value,_>("entitlements"),"seat":1});
    let token = sign_token(&signer, &key_id, "GMT", &payload).map_err(|_| bad("invalid_claims"))?;
    sqlx::query("INSERT INTO certificates(license_id,revision,binding_version,serial,key_id,token,reason) VALUES($1,$2,1,$3,$4,$5,$6)").bind(id).bind(revision).bind(serial).bind(key_id).bind(token).bind(reason).execute(&mut **tx).await?;
    sqlx::query(
        "UPDATE renewals SET serial=$3 WHERE license_id=$1 AND revision=$2 AND serial IS NULL",
    )
    .bind(id)
    .bind(revision)
    .bind(serial)
    .execute(&mut **tx)
    .await?;
    Ok(Some(serial))
}
pub async fn activate(State(s): State<AppState>, StrictJson(v): StrictJson) -> Result<Json<Value>> {
    consume(s, v, "activate").await
}
pub async fn sync(State(s): State<AppState>, StrictJson(v): StrictJson) -> Result<Json<Value>> {
    consume(s, v, "sync").await
}
pub async fn ack(State(s): State<AppState>, StrictJson(v): StrictJson) -> Result<Json<Value>> {
    consume(s, v, "ack").await
}
async fn consume(s: AppState, v: Value, op: &str) -> Result<Json<Value>> {
    let app = uuid(&v, "productId")?;
    let license = uuid(&v, "licenseId")?;
    let id = uuid(&v, "challengeId")?;
    let idem = idempotency(&v)?;
    let signature = decode::<64>(field(&v, "signature")?, false)?;
    let request_hash =
        hash(grantmint_license_protocol::canonical_json(&v).map_err(|_| bad("invalid_request"))?);
    let mut tx = s.pool.begin().await?;
    let l = locked(&mut tx, license, Some(app)).await?;
    usable(&l, op != "ack")?;
    let ch = sqlx::query(
        "SELECT * FROM challenges WHERE id=$1 AND license_id=$2 AND operation=$3 FOR UPDATE",
    )
    .bind(id)
    .bind(license)
    .bind(op)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(unauthorized())?;
    let key: String = ch.get("device_public_key");
    let fp: String = ch.get("fingerprint_hash");
    let pubkey = decode::<32>(&key, true)?;
    VerifyingKey::from_bytes(&pubkey)
        .map_err(|_| bad("invalid_device_key"))?
        .verify_strict(
            message(&ch, app, license).as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| Error(StatusCode::UNAUTHORIZED, "invalid_device_proof"))?;
    let bound = binding(&mut tx, license, &key, &fp).await?;
    if let Some(response) = ch.get::<Option<Value>, _>("response") {
        if ch.get::<Option<Vec<u8>>, _>("request_hash").as_ref() != Some(&request_hash) {
            return Err(conflict("idempotency_conflict"));
        }
        return Ok(Json(response));
    }
    if ch.get::<DateTime<Utc>, _>("expires_at") <= Utc::now() {
        return Err(Error(StatusCode::UNPROCESSABLE_ENTITY, "challenge_expired"));
    }
    let used:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM challenges WHERE license_id=$1 AND operation=$2 AND idempotency_key=$3)").bind(license).bind(op).bind(idem).fetch_one(&mut *tx).await?;
    if used {
        return Err(conflict("idempotency_conflict"));
    }
    if op == "activate" && bound.is_none() {
        sqlx::query("INSERT INTO device_bindings(license_id,device_public_key,fingerprint_hash,fingerprint_version) VALUES($1,$2,$3,1)").bind(license).bind(&key).bind(&fp).execute(&mut *tx).await?;
        issue_certificate(&s, &mut tx, &l, "activation").await?;
        audit(
            &mut tx,
            "device",
            app,
            Some(license),
            "license.activated",
            json!({"deviceKeyHash":device_key_hash(&pubkey)}),
        )
        .await?;
    } else if bound.is_none() {
        return Err(unauthorized());
    }
    let serial = current_serial(&mut tx, &l).await?;
    if op != "activate" && ch.get::<Option<Uuid>, _>("serial") != Some(serial) {
        return Err(conflict("certificate_changed"));
    }
    let response = if op == "ack" {
        if uuid(&v, "serial")? != serial {
            return Err(conflict("certificate_changed"));
        }
        let now = Utc::now();
        sqlx::query("UPDATE renewals SET confirmed_at=COALESCE(confirmed_at,$3) WHERE license_id=$1 AND serial=$2").bind(license).bind(serial).bind(now).execute(&mut *tx).await?;
        sqlx::query(
            "UPDATE certificates SET confirmed_at=COALESCE(confirmed_at,$2) WHERE serial=$1",
        )
        .bind(serial)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        audit(
            &mut tx,
            "device",
            app,
            Some(license),
            "license.acknowledged",
            json!({"serial":serial}),
        )
        .await?;
        json!({"serial":serial,"confirmedAt":now})
    } else {
        let token: String = sqlx::query_scalar("SELECT token FROM certificates WHERE serial=$1")
            .bind(serial)
            .fetch_one(&mut *tx)
            .await?;
        let key_id: String = l.get("signing_key_id");
        let signer = s.keys.signer(&key_id)?;
        let now = Utc::now().timestamp();
        if now >= l.get::<DateTime<Utc>, _>("expires_at").timestamp() {
            return Err(Error(StatusCode::UNPROCESSABLE_ENTITY, "license_expired"));
        }
        let payload = json!({"ver":2,"operation":op,"challenge_id":id,"nonce":ch.get::<String,_>("nonce"),"product_id":app,"lid":license,"device_key_hash":device_key_hash(&pubkey),"serial":serial,"server_time":now});
        let receipt = sign_token(&signer, &key_id, "GMT-TIME", &payload)
            .map_err(|_| bad("invalid_claims"))?;
        json!({"licenseId":license,"keyId":l.get::<String,_>("key_id"),"token":token,"revision":l.get::<i64,_>("revision"),"bindingVersion":1,"serverTime":now,"timeReceipt":receipt})
    };
    sqlx::query("UPDATE challenges SET consumed_at=now(),idempotency_key=$2,request_hash=$3,response=$4 WHERE id=$1").bind(id).bind(idem).bind(request_hash).bind(&response).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(response))
}
