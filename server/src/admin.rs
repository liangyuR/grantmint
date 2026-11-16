use crate::json::StrictJson;
use crate::{
    audit,
    auth::Admin,
    device,
    error::{bad, conflict, field, time, uuid, Error, Result},
    hash, secret, AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

const APP_JSON:&str="SELECT jsonb_build_object('id',id,'slug',slug,'name',name,'description',description,'signingKeyId',signing_key_id,'archivedAt',archived_at,'createdAt',created_at) FROM applications";
async fn app(conn: &mut PgConnection, id: Uuid) -> Result<Value> {
    sqlx::query_scalar(&format!("{APP_JSON} WHERE id=$1"))
        .bind(id)
        .fetch_optional(conn)
        .await?
        .ok_or(Error(StatusCode::NOT_FOUND, "application_not_found"))
}
pub async fn applications(State(s): State<AppState>) -> Result<Json<Vec<Value>>> {
    Ok(Json(
        sqlx::query_scalar(&format!("{APP_JSON} ORDER BY created_at DESC"))
            .fetch_all(&s.pool)
            .await?,
    ))
}
pub async fn application(State(s): State<AppState>, Path(id): Path<Uuid>) -> Result<Json<Value>> {
    Ok(Json(app(&mut *s.pool.acquire().await?, id).await?))
}
pub async fn configured_keys(State(s): State<AppState>) -> Result<Json<Vec<Value>>> {
    let mut out = vec![];
    for c in s.keys.entries.values() {
        let owner: Option<Uuid> =
            sqlx::query_scalar("SELECT application_id FROM signing_keys WHERE key_id=$1")
                .bind(&c.key_id)
                .fetch_optional(&s.pool)
                .await?;
        out.push(json!({"keyId":c.key_id,"publicKey":c.public_key,"applicationId":owner}));
    }
    out.sort_by_key(|v| v["keyId"].as_str().unwrap().to_string());
    Ok(Json(out))
}
async fn bind_key(s: &AppState, conn: &mut PgConnection, id: Uuid, key: &str) -> Result<()> {
    let configured = s.keys.entries.get(key).ok_or(bad("unknown_signing_key"))?;
    s.keys.signer(key)?;
    sqlx::query("INSERT INTO signing_keys(key_id,application_id,public_key) VALUES($1,$2,$3) ON CONFLICT(key_id) DO NOTHING").bind(key).bind(id).bind(&configured.public_key).execute(&mut *conn).await?;
    let row = sqlx::query("SELECT application_id,public_key FROM signing_keys WHERE key_id=$1")
        .bind(key)
        .fetch_one(conn)
        .await?;
    if row.get::<Uuid, _>("application_id") != id
        || row.get::<String, _>("public_key") != configured.public_key
    {
        return Err(conflict("signing_key_conflict"));
    }
    Ok(())
}
fn name(v: &Value) -> Result<&str> {
    let n = field(v, "name")?;
    if n.trim().is_empty() || n.len() > 200 {
        return Err(bad("invalid_name"));
    }
    Ok(n)
}
pub async fn create_application(
    State(s): State<AppState>,
    Extension(a): Extension<Admin>,
    StrictJson(v): StrictJson,
) -> Result<(StatusCode, Json<Value>)> {
    let id = if v.get("id").is_some() {
        uuid(&v, "id")?
    } else {
        Uuid::new_v4()
    };
    let slug = field(&v, "slug")?;
    if slug.len() > 100
        || !slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(bad("invalid_slug"));
    }
    let key = field(&v, "signingKeyId")?;
    let mut tx = s.pool.begin().await?;
    sqlx::query(
        "INSERT INTO applications(id,slug,name,description,signing_key_id) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(id)
    .bind(slug)
    .bind(name(&v)?)
    .bind(v["description"].as_str().unwrap_or(""))
    .bind(key)
    .execute(&mut *tx)
    .await?;
    bind_key(&s, &mut tx, id, key).await?;
    audit(
        &mut tx,
        &a.username,
        id,
        None,
        "application.created",
        json!({"signingKeyId":key}),
    )
    .await?;
    let result = app(&mut tx, id).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(result)))
}
pub async fn update_application(
    State(s): State<AppState>,
    Extension(a): Extension<Admin>,
    Path(id): Path<Uuid>,
    StrictJson(v): StrictJson,
) -> Result<Json<Value>> {
    let mut tx = s.pool.begin().await?;
    let old = sqlx::query("SELECT signing_key_id FROM applications WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error(StatusCode::NOT_FOUND, "application_not_found"))?;
    let key = field(&v, "signingKeyId")?;
    bind_key(&s, &mut tx, id, key).await?;
    sqlx::query("UPDATE applications SET name=$2,description=$3,signing_key_id=$4 WHERE id=$1")
        .bind(id)
        .bind(name(&v)?)
        .bind(v["description"].as_str().unwrap_or(""))
        .bind(key)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        &a.username,
        id,
        None,
        "application.updated",
        json!({"previousKeyId":old.get::<String,_>("signing_key_id"),"signingKeyId":key}),
    )
    .await?;
    let result = app(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Json(result))
}
pub async fn archive_application(
    State(s): State<AppState>,
    Extension(a): Extension<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    let mut tx = s.pool.begin().await?;
    let changed =
        sqlx::query("UPDATE applications SET archived_at=COALESCE(archived_at,now()) WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    if changed.rows_affected() == 0 {
        return Err(Error(StatusCode::NOT_FOUND, "application_not_found"));
    }
    audit(
        &mut tx,
        &a.username,
        id,
        None,
        "application.archived",
        json!({}),
    )
    .await?;
    let result = app(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Json(result))
}
pub async fn application_keys(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Value>>> {
    Ok(Json(sqlx::query_scalar("SELECT jsonb_build_object('keyId',k.key_id,'publicKey',k.public_key,'active',k.key_id=a.signing_key_id) FROM signing_keys k JOIN applications a ON a.id=k.application_id WHERE a.id=$1 ORDER BY k.created_at").bind(id).fetch_all(&s.pool).await?))
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub application_id: Option<Uuid>,
    pub license_id: Option<Uuid>,
    pub page: Option<i64>,
    pub size: Option<i64>,
}
impl Page {
    fn bounds(&self) -> (i64, i64) {
        (
            self.page.unwrap_or(0).clamp(0, 1_000_000),
            self.size.unwrap_or(50).clamp(1, 100),
        )
    }
}
fn page_json(content: Vec<Value>, total: i64, page: i64, size: i64) -> Value {
    json!({"content":content,"totalElements":total,"totalPages":(total+size-1)/size,"number":page,"size":size})
}
pub async fn detail(conn: &mut PgConnection, id: Uuid) -> Result<Value> {
    let row=sqlx::query("SELECT l.*,a.name application_name,b.device_public_key,b.fingerprint_hash,b.fingerprint_version,b.binding_version,c.token,c.serial,c.confirmed_at FROM licenses l JOIN applications a ON a.id=l.application_id LEFT JOIN device_bindings b ON b.license_id=l.id LEFT JOIN certificates c ON c.license_id=l.id AND c.revision=l.revision AND c.binding_version=b.binding_version WHERE l.id=$1").bind(id).fetch_optional(&mut *conn).await?.ok_or(Error(StatusCode::NOT_FOUND,"license_not_found"))?;
    let renewals:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'oldExpiresAt',old_expires_at,'newExpiresAt',new_expires_at,'revision',revision,'serial',serial,'confirmedAt',confirmed_at,'reason',reason,'createdAt',created_at) FROM renewals WHERE license_id=$1 ORDER BY revision DESC").bind(id).fetch_all(conn).await?;
    let revoked = row.get::<Option<DateTime<Utc>>, _>("revoked_at");
    let expiry: DateTime<Utc> = row.get("expires_at");
    let binding: Option<i64> = row.get("binding_version");
    let delivery = if binding.is_none() {
        "not_activated"
    } else if row
        .get::<Option<DateTime<Utc>>, _>("confirmed_at")
        .is_none()
    {
        "pending"
    } else {
        "confirmed"
    };
    Ok(
        json!({"id":id,"keyId":row.get::<String,_>("key_id"),"applicationId":row.get::<Uuid,_>("application_id"),"applicationName":row.get::<String,_>("application_name"),"customer":row.get::<Value,_>("customer"),"expiresAt":expiry,"entitlements":row.get::<Value,_>("entitlements"),"status":if revoked.is_some(){"revoked"}else if Utc::now()>=expiry{"expired"}else if binding.is_some(){"active"}else{"created"},"revision":row.get::<i64,_>("revision"),"bindingVersion":binding.unwrap_or(0),"createdAt":row.get::<DateTime<Utc>,_>("created_at"),"revokedAt":revoked,"signedToken":row.get::<Option<String>,_>("token"),"devicePublicKey":row.get::<Option<String>,_>("device_public_key"),"fingerprintHash":row.get::<Option<String>,_>("fingerprint_hash"),"fingerprintVersion":row.get::<Option<i32>,_>("fingerprint_version"),"serial":row.get::<Option<Uuid>,_>("serial"),"deliveryStatus":delivery,"renewals":renewals}),
    )
}
pub async fn licenses(State(s): State<AppState>, Query(p): Query<Page>) -> Result<Json<Value>> {
    let (page, size) = p.bounds();
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM licenses WHERE ($1::uuid IS NULL OR application_id=$1)",
    )
    .bind(p.application_id)
    .fetch_one(&s.pool)
    .await?;
    let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM licenses WHERE ($1::uuid IS NULL OR application_id=$1) ORDER BY created_at DESC,id LIMIT $2 OFFSET $3").bind(p.application_id).bind(size).bind(page*size).fetch_all(&s.pool).await?;
    let mut conn = s.pool.acquire().await?;
    let mut content = vec![];
    for id in ids {
        content.push(detail(&mut conn, id).await?)
    }
    Ok(Json(page_json(content, total, page, size)))
}
pub async fn license(State(s): State<AppState>, Path(id): Path<Uuid>) -> Result<Json<Value>> {
    Ok(Json(detail(&mut *s.pool.acquire().await?, id).await?))
}
pub async fn create_license(
    State(s): State<AppState>,
    Extension(a): Extension<Admin>,
    StrictJson(v): StrictJson,
) -> Result<(StatusCode, Json<Value>)> {
    let app_id = uuid(&v, "applicationId")?;
    let expiry = time(&v, "expiresAt")?;
    if expiry <= Utc::now() {
        return Err(bad("invalid_expiry"));
    }
    let customer = v.get("customer").ok_or(bad("invalid_customer"))?;
    field(customer, "name")?;
    field(customer, "email")?;
    let ent = v.get("entitlements").cloned().unwrap_or(json!({}));
    let obj = ent.as_object().ok_or(bad("invalid_entitlements"))?;
    if obj.values().any(|x| {
        !x.is_boolean()
            && !x.is_string()
            && !x
                .as_i64()
                .is_some_and(|n| n.unsigned_abs() <= 9_007_199_254_740_991)
    }) {
        return Err(bad("invalid_entitlements"));
    }
    let mut tx = s.pool.begin().await?;
    let archived: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT archived_at FROM applications WHERE id=$1 FOR UPDATE")
            .bind(app_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error(StatusCode::NOT_FOUND, "application_not_found"))?;
    if archived.is_some() {
        return Err(conflict("application_archived"));
    }
    let id = Uuid::new_v4();
    let secret = secret();
    let key_id = format!("LIC-{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO licenses(id,application_id,key_id,customer,expires_at,entitlements,activation_secret_hash) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(id).bind(app_id).bind(key_id).bind(customer).bind(expiry).bind(ent).bind(hash(&secret)).execute(&mut *tx).await?;
    audit(
        &mut tx,
        &a.username,
        app_id,
        Some(id),
        "license.created",
        json!({"expiresAt":expiry}),
    )
    .await?;
    let mut result = detail(&mut tx, id).await?;
    result["licenseId"] = json!(id);
    result["activationSecret"] = json!(secret);
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(result)))
}
pub async fn revoke(
    State(s): State<AppState>,
    Extension(a): Extension<Admin>,
    Path(id): Path<Uuid>,
    StrictJson(v): StrictJson,
) -> Result<Json<Value>> {
    let reason = field(&v, "reason")?;
    let mut tx = s.pool.begin().await?;
    let l = device::locked(&mut tx, id, None).await?;
    sqlx::query("UPDATE licenses SET revoked_at=COALESCE(revoked_at,now()),revoke_reason=COALESCE(revoke_reason,$2) WHERE id=$1").bind(id).bind(reason).execute(&mut *tx).await?;
    audit(
        &mut tx,
        &a.username,
        l.get("application_id"),
        Some(id),
        "license.revoked",
        json!({"reason":reason}),
    )
    .await?;
    let result = detail(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Json(result))
}
pub async fn renew(
    State(s): State<AppState>,
    Extension(a): Extension<Admin>,
    Path(id): Path<Uuid>,
    StrictJson(v): StrictJson,
) -> Result<Json<Value>> {
    let idem = device::idempotency(&v)?;
    let expected = v["expectedRevision"]
        .as_i64()
        .ok_or(bad("invalid_revision"))?;
    let expiry = time(&v, "newExpiresAt")?;
    let reason = field(&v, "reason")?;
    let request_hash =
        hash(grantmint_license_protocol::canonical_json(&v).map_err(|_| bad("invalid_request"))?);
    let mut tx = s.pool.begin().await?;
    let l = device::locked(&mut tx, id, None).await?;
    if let Some(previous) = sqlx::query(
        "SELECT request_hash,response FROM renewals WHERE license_id=$1 AND idempotency_key=$2",
    )
    .bind(id)
    .bind(idem)
    .fetch_optional(&mut *tx)
    .await?
    {
        if previous.get::<Vec<u8>, _>("request_hash") != request_hash {
            return Err(conflict("idempotency_conflict"));
        }
        return Ok(Json(previous.get("response")));
    }
    if l.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some() {
        return Err(conflict("license_revoked"));
    }
    if l.get::<Option<DateTime<Utc>>, _>("archived_at").is_some() {
        return Err(conflict("application_archived"));
    }
    let old: DateTime<Utc> = l.get("expires_at");
    let revision: i64 = l.get("revision");
    if expected != revision {
        return Err(conflict("revision_conflict"));
    }
    if expiry <= old || expiry <= Utc::now() || revision >= 9_007_199_254_740_991 {
        return Err(bad("invalid_expiry"));
    }
    sqlx::query("UPDATE licenses SET expires_at=$2,revision=revision+1 WHERE id=$1")
        .bind(id)
        .bind(expiry)
        .execute(&mut *tx)
        .await?;
    let updated = device::locked(&mut tx, id, None).await?;
    let serial = device::issue_certificate(&s, &mut tx, &updated, "renewal").await?;
    let renewal = Uuid::new_v4();
    sqlx::query("INSERT INTO renewals(id,license_id,idempotency_key,request_hash,old_expires_at,new_expires_at,revision,serial,actor,reason,response) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'{}')").bind(renewal).bind(id).bind(idem).bind(request_hash).bind(old).bind(expiry).bind(revision+1).bind(serial).bind(&a.username).bind(reason).execute(&mut *tx).await?;
    audit(
        &mut tx,
        &a.username,
        l.get("application_id"),
        Some(id),
        "license.renewed",
        json!({"revision":revision+1,"expiresAt":expiry,"reason":reason}),
    )
    .await?;
    let result = detail(&mut tx, id).await?;
    sqlx::query("UPDATE renewals SET response=$2 WHERE id=$1")
        .bind(renewal)
        .bind(&result)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(result))
}
pub async fn audit_list(State(s): State<AppState>, Query(p): Query<Page>) -> Result<Json<Value>> {
    let (page, size) = p.bounds();
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE ($1::uuid IS NULL OR application_id=$1) AND ($2::uuid IS NULL OR license_id=$2)").bind(p.application_id).bind(p.license_id).fetch_one(&s.pool).await?;
    let values=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'actor',actor,'applicationId',application_id,'licenseId',license_id,'action',action,'detail',detail,'createdAt',created_at) FROM audit_events WHERE ($1::uuid IS NULL OR application_id=$1) AND ($2::uuid IS NULL OR license_id=$2) ORDER BY id DESC LIMIT $3 OFFSET $4").bind(p.application_id).bind(p.license_id).bind(size).bind(page*size).fetch_all(&s.pool).await?;
    Ok(Json(page_json(values, count, page, size)))
}
