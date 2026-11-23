pub mod admin;
pub mod auth;
pub mod device;
pub mod error;
pub mod json;
pub mod signing;
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use error::{Error, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub keys: Arc<signing::Keys>,
    pub secure_cookie: bool,
    pub origin: String,
    pub trusted_proxies: Vec<IpAddr>,
    pub limits: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
}
pub fn hash(input: impl AsRef<[u8]>) -> Vec<u8> {
    Sha256::digest(input.as_ref()).to_vec()
}
pub fn secret() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub async fn connect() -> std::result::Result<PgPool, Box<dyn std::error::Error>> {
    let options = if let Ok(url) = std::env::var("DATABASE_URL") {
        url.parse::<PgConnectOptions>()?
    } else {
        PgConnectOptions::new()
            .host(&std::env::var("DB_HOST").unwrap_or("localhost".into()))
            .port(std::env::var("DB_PORT").unwrap_or("5432".into()).parse()?)
            .database(&std::env::var("DB_NAME").unwrap_or("grantmint".into()))
            .username(&std::env::var("DB_USER").unwrap_or("grantmint".into()))
            .password(&std::env::var("DB_PASSWORD").unwrap_or_default())
    };
    Ok(PgPoolOptions::new()
        .max_connections(20)
        .connect_with(options)
        .await?)
}
pub async fn migrate(pool: &PgPool) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let legacy: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.flyway_schema_history')::text")
            .fetch_one(pool)
            .await?;
    if legacy.is_some() {
        return Err("refusing to mix SQLx and Flyway databases".into());
    }
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}
pub async fn validate_schema(pool: &PgPool) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use sqlx::Row;
    let legacy: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.flyway_schema_history')::text")
            .fetch_one(pool)
            .await?;
    if legacy.is_some() {
        return Err("refusing to mix SQLx and Flyway databases".into());
    }
    let applied =
        sqlx::query("SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await?;
    let migrations = sqlx::migrate!("./migrations");
    if applied.len() != migrations.iter().count() {
        return Err("run migrate before serving: schema version mismatch".into());
    }
    for (row, migration) in applied.iter().zip(migrations.iter()) {
        if row.get::<i64, _>("version") != migration.version
            || !row.get::<bool, _>("success")
            || row.get::<Vec<u8>, _>("checksum") != migration.checksum.as_ref()
        {
            return Err("migration checksum/version mismatch".into());
        }
    }
    Ok(())
}
pub fn router(state: AppState) -> Router {
    let admin = Router::new()
        .route("/auth/me", get(auth::me))
        .route("/auth/logout", post(auth::logout))
        .route("/v2/signing-keys", get(admin::configured_keys))
        .route(
            "/v2/applications",
            get(admin::applications).post(admin::create_application),
        )
        .route(
            "/v2/applications/{id}",
            get(admin::application).put(admin::update_application),
        )
        .route(
            "/v2/applications/{id}/archive",
            post(admin::archive_application),
        )
        .route("/v2/applications/{id}/keys", get(admin::application_keys))
        .route(
            "/v2/licenses",
            get(admin::licenses).post(admin::create_license),
        )
        .route("/v2/licenses/{id}", get(admin::license))
        .route("/v2/licenses/{id}/revoke", post(admin::revoke))
        .route("/v2/licenses/{id}/renewals", post(admin::renew))
        .route("/v2/audit", get(admin::audit_list))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::guard));
    Router::new()
        .nest("/admin", admin)
        .route("/admin/auth/login", post(auth::login))
        .route("/v2/licenses/challenges", post(device::challenge))
        .route("/v2/licenses/activate", post(device::activate))
        .route("/v2/licenses/sync-challenges", post(device::sync_challenge))
        .route("/v2/licenses/sync", post(device::sync))
        .route("/v2/licenses/acknowledgements", post(device::ack))
        .route("/healthz", get(health))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}
async fn health(State(s): State<AppState>) -> Result<Json<Value>> {
    sqlx::query("SELECT 1").execute(&s.pool).await?;
    Ok(Json(json!({"status":"ok"})))
}
async fn boundary(State(s): State<AppState>, req: Request, next: Next) -> Result<Response> {
    if req.uri().path().starts_with("/admin") && req.method() != Method::GET {
        if let Some(origin) = req.headers().get("origin") {
            if origin.to_str().ok() != Some(s.origin.as_str()) {
                return Err(Error(StatusCode::FORBIDDEN, "invalid_origin"));
            }
        }
    }
    let path = req.uri().path();
    let login = path == "/admin/auth/login";
    if login || path.starts_with("/v2/") {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|x| x.0.ip());
        let mut ip = peer.map(|p| p.to_string()).unwrap_or("local".into());
        if peer.is_some_and(|p| s.trusted_proxies.contains(&p)) {
            if let Some(chain) = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|h| h.to_str().ok())
            {
                for hop in chain.split(',').rev() {
                    let Ok(addr) = hop.trim().parse::<IpAddr>() else {
                        break;
                    };
                    if !s.trusted_proxies.contains(&addr) {
                        ip = addr.to_string();
                        break;
                    }
                }
            }
        }
        let key = format!("{}:{}", if login { "login" } else { "device" }, ip);
        let mut limits = s
            .limits
            .lock()
            .map_err(|_| Error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))?;
        limits.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(60));
        if limits.len() >= 10000 && !limits.contains_key(&key) {
            return Err(Error(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
        }
        let entry = limits.entry(key).or_insert((Instant::now(), 0));
        entry.1 += 1;
        if entry.1 > if login { 10 } else { 60 } {
            return Err(Error(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
        }
    }
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    Ok(response)
}
pub async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &str,
    app: uuid::Uuid,
    license: Option<uuid::Uuid>,
    action: &str,
    detail: Value,
) -> Result<()> {
    sqlx::query("INSERT INTO audit_events(actor,application_id,license_id,action,detail) VALUES($1,$2,$3,$4,$5)").bind(actor).bind(app).bind(license).bind(action).bind(detail).execute(&mut **tx).await?;
    Ok(())
}
pub async fn cleanup(pool: &PgPool) -> Result<()> {
    sqlx::query("DELETE FROM challenges WHERE expires_at < now() AND (response IS NULL OR consumed_at < now()-interval '24 hours')").execute(pool).await?;
    sqlx::query("DELETE FROM admin_sessions WHERE expires_at < $1")
        .bind(Utc::now())
        .execute(pool)
        .await?;
    Ok(())
}
