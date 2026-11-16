use crate::json::StrictJson;
use crate::{
    error::{bad, field, Error, Result},
    hash, secret, AppState,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Extension, Json,
};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use subtle::ConstantTimeEq;
use uuid::Uuid;
#[derive(Clone)]
pub struct Admin {
    pub username: String,
    pub token_hash: Vec<u8>,
    pub csrf: String,
}
pub async fn bootstrap(pool: &PgPool) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(817234892)")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_users")
        .fetch_one(&mut *tx)
        .await?;
    if count == 0 {
        let user = std::env::var("ADMIN_USERNAME").unwrap_or("admin".into());
        let password = std::env::var("ADMIN_PASSWORD")?;
        if user.is_empty() || password.len() < 12 {
            return Err("ADMIN_PASSWORD must contain at least 12 characters".into());
        }
        let encoded = Argon2::default()
            .hash_password(
                password.as_bytes(),
                &SaltString::generate(&mut rand::rngs::OsRng),
            )
            .map_err(|_| "password hashing failed")?
            .to_string();
        sqlx::query("INSERT INTO admin_users(id,username,password_hash) VALUES($1,$2,$3)")
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(encoded)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
pub async fn login(
    State(s): State<AppState>,
    StrictJson(v): StrictJson,
) -> Result<(HeaderMap, Json<Value>)> {
    let username = field(&v, "username")?.to_owned();
    let password = field(&v, "password")?.to_owned();
    if password.len() > 1024 || username.len() > 128 {
        return Err(bad("invalid_request"));
    }
    let row =
        sqlx::query("SELECT id,password_hash FROM admin_users WHERE username=$1 AND NOT disabled")
            .bind(&username)
            .fetch_optional(&s.pool)
            .await?;
    let Some(row) = row else {
        return Err(Error(StatusCode::UNAUTHORIZED, "invalid_credentials"));
    };
    let encoded: String = row.get("password_hash");
    let valid = tokio::task::spawn_blocking(move || {
        PasswordHash::new(&encoded).is_ok_and(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
    })
    .await
    .map_err(|_| Error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))?;
    if !valid {
        return Err(Error(StatusCode::UNAUTHORIZED, "invalid_credentials"));
    }
    let token = secret();
    let csrf = secret();
    sqlx::query(
        "INSERT INTO admin_sessions(token_hash,admin_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)",
    )
    .bind(hash(&token))
    .bind(row.get::<Uuid, _>("id"))
    .bind(&csrf)
    .bind(Utc::now() + Duration::hours(8))
    .execute(&s.pool)
    .await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "set-cookie",
        cookie(&token, s.secure_cookie, 28800).parse().unwrap(),
    );
    Ok((headers, Json(json!({"username":username,"csrfToken":csrf}))))
}
fn cookie(token: &str, secure: bool, age: u32) -> String {
    format!(
        "grantmint_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{}",
        if secure { "; Secure" } else { "" }
    )
}
pub async fn guard(State(s): State<AppState>, mut req: Request, next: Next) -> Result<Response> {
    let token = req
        .headers()
        .get("cookie")
        .and_then(|x| x.to_str().ok())
        .and_then(|x| {
            x.split(';')
                .find_map(|p| p.trim().strip_prefix("grantmint_session="))
        })
        .filter(|x| x.len() == 64)
        .ok_or(Error(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    let token_hash = hash(token);
    let row=sqlx::query("SELECT u.username,s.csrf_token FROM admin_sessions s JOIN admin_users u ON u.id=s.admin_id WHERE s.token_hash=$1 AND s.expires_at>now() AND NOT u.disabled").bind(&token_hash).fetch_optional(&s.pool).await?.ok_or(Error(StatusCode::UNAUTHORIZED,"unauthorized"))?;
    let csrf: String = row.get("csrf_token");
    if req.method() != axum::http::Method::GET && req.method() != axum::http::Method::HEAD {
        let supplied = req
            .headers()
            .get("x-xsrf-token")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        if !bool::from(supplied.as_bytes().ct_eq(csrf.as_bytes())) {
            return Err(Error(StatusCode::FORBIDDEN, "csrf_invalid"));
        }
    }
    req.extensions_mut().insert(Admin {
        username: row.get("username"),
        token_hash,
        csrf,
    });
    Ok(next.run(req).await)
}
pub async fn me(Extension(a): Extension<Admin>) -> Json<Value> {
    Json(json!({"username":a.username,"csrfToken":a.csrf}))
}
pub async fn logout(
    State(s): State<AppState>,
    Extension(a): Extension<Admin>,
) -> Result<(StatusCode, HeaderMap)> {
    sqlx::query("DELETE FROM admin_sessions WHERE token_hash=$1")
        .bind(a.token_hash)
        .execute(&s.pool)
        .await?;
    let mut h = HeaderMap::new();
    h.insert(
        "set-cookie",
        cookie("", s.secure_cookie, 0).parse().unwrap(),
    );
    Ok((StatusCode::NO_CONTENT, h))
}
