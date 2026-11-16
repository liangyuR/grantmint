use grantmint_server::{
    auth, connect, migrate, router,
    signing::{self, Keys},
    validate_schema, AppState,
};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("serve");
    let key_root = PathBuf::from(std::env::var("KEYS_DIR").unwrap_or("/keys".into()));
    if command == "keygen" {
        return signing::keygen(
            &key_root,
            args.get(2).ok_or("keygen KEY_ID FILE")?,
            args.get(3).ok_or("keygen KEY_ID FILE")?,
        );
    }
    let pool = connect().await?;
    if command == "migrate" {
        return migrate(&pool).await;
    }
    if command != "serve" {
        return Err("usage: grantmint-server migrate|serve|keygen KEY_ID FILE".into());
    }
    validate_schema(&pool).await?;
    auth::bootstrap(&pool).await?;
    let keys = Keys::load(
        key_root,
        &PathBuf::from(
            std::env::var("SIGNING_KEYS_FILE").unwrap_or("/config/signing-keys.json".into()),
        ),
    )?;
    for entry in keys.entries.values() {
        let stored: Option<String> =
            sqlx::query_scalar("SELECT public_key FROM signing_keys WHERE key_id=$1")
                .bind(&entry.key_id)
                .fetch_optional(&pool)
                .await?;
        if stored.as_ref().is_some_and(|p| p != &entry.public_key) {
            return Err("configured key ID has a different persisted public key".into());
        }
    }
    let state = AppState {
        pool: pool.clone(),
        keys: Arc::new(keys),
        secure_cookie: std::env::var("COOKIE_SECURE").unwrap_or("true".into()) != "false",
        origin: std::env::var("PUBLIC_ORIGIN").unwrap_or("http://localhost:8080".into()),
        trusted_proxies: std::env::var("TRUSTED_PROXY_IPS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::parse)
            .collect::<Result<_, _>>()?,
        limits: Arc::new(Mutex::new(HashMap::new())),
    };
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = grantmint_server::cleanup(&pool).await {
                tracing::error!(error=?e,"cleanup failed")
            }
        }
    });
    let listener =
        tokio::net::TcpListener::bind(std::env::var("BIND_ADDR").unwrap_or("0.0.0.0:8080".into()))
            .await?;
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
