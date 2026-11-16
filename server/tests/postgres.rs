use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use grantmint_server::{router, signing::Keys, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

struct Harness {
    root: PgPool,
    pool: PgPool,
    schema: String,
    router: Router,
    cookie: String,
    csrf: String,
    app: String,
    keys: TempDir,
}
impl Harness {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").expect(
            "TEST_DATABASE_URL must point to PostgreSQL; integration tests never silently skip",
        );
        let root = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&root)
            .await
            .unwrap();
        let scoped = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .after_connect(move |conn, _| {
                let query = format!("SET search_path TO {scoped}");
                Box::pin(async move {
                    sqlx::query(&query).execute(conn).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../migrations/0001_initial.sql"))
            .execute(&pool)
            .await
            .unwrap();
        let encoded = Argon2::default()
            .hash_password(
                b"integration-only-password",
                &SaltString::generate(&mut rand::rngs::OsRng),
            )
            .unwrap()
            .to_string();
        sqlx::query("INSERT INTO admin_users(id,username,password_hash) VALUES($1,'operator',$2)")
            .bind(Uuid::new_v4())
            .bind(encoded)
            .execute(&pool)
            .await
            .unwrap();
        let keys = tempfile::tempdir().unwrap();
        std::fs::write(keys.path().join("seed"), [7u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                keys.path().join("seed"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let config = keys.path().join("keys.json");
        std::fs::write(&config,json!([{"keyId":"test-key","publicKey":STANDARD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes()),"privateKeyFile":"seed"}]).to_string()).unwrap();
        let state = AppState {
            pool: pool.clone(),
            keys: Arc::new(Keys::load(keys.path().to_path_buf(), &config).unwrap()),
            secure_cookie: false,
            origin: "http://localhost".into(),
            trusted_proxies: vec![],
            limits: Arc::new(Mutex::new(HashMap::new())),
        };
        let router = router(state);
        let login = router
            .clone()
            .oneshot(
                Request::post("/admin/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"username":"operator","password":"integration-only-password"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = login.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body: Value =
            serde_json::from_slice(&login.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let mut h = Self {
            root,
            pool,
            schema,
            router,
            cookie,
            csrf: body["csrfToken"].as_str().unwrap().into(),
            app: String::new(),
            keys,
        };
        let (status, app) = h
            .call(
                Method::POST,
                "/admin/v2/applications",
                json!({"slug":"test-app","name":"测试应用","signingKeyId":"test-key"}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{app}");
        h.app = app["id"].as_str().unwrap().into();
        h
    }
    async fn call(&self, method: Method, path: &str, value: Value) -> (StatusCode, Value) {
        request(
            &self.router,
            method,
            path,
            value,
            Some((&self.cookie, &self.csrf)),
        )
        .await
    }
    async fn device(&self, path: &str, value: Value) -> (StatusCode, Value) {
        request(&self.router, Method::POST, path, value, None).await
    }
    async fn license(&self) -> Value {
        let(status,v)=self.call(Method::POST,"/admin/v2/licenses",json!({"applicationId":self.app,"customer":{"name":"客户","email":"test@example.invalid"},"expiresAt":Utc::now()+Duration::days(30),"entitlements":{"inspect":true}})).await;
        assert_eq!(status, StatusCode::CREATED, "{v}");
        v
    }
    async fn challenge(&self, l: &Value, d: &SigningKey, op: &str, serial: Option<&str>) -> Value {
        let mut v = json!({"productId":self.app,"licenseId":l["id"],"devicePublicKey":STANDARD.encode(d.verifying_key().as_bytes()),"fingerprintHash":URL_SAFE_NO_PAD.encode([3u8;32]),"fingerprintVersion":1});
        let path = if op == "activate" {
            v["activationSecret"] = l["activationSecret"].clone();
            "/v2/licenses/challenges"
        } else {
            v["operation"] = json!(op);
            if let Some(serial) = serial {
                v["serial"] = json!(serial)
            }
            "/v2/licenses/sync-challenges"
        };
        let (status, ch) = self.device(path, v).await;
        assert_eq!(status, StatusCode::OK, "{ch}");
        ch
    }
    fn proof(&self, l: &Value, d: &SigningKey, ch: &Value) -> Value {
        json!({"productId":self.app,"licenseId":l["id"],"challengeId":ch["challengeId"],"signature":URL_SAFE_NO_PAD.encode(d.sign(&URL_SAFE_NO_PAD.decode(ch["message"].as_str().unwrap()).unwrap()).to_bytes()),"idempotencyKey":Uuid::new_v4()})
    }
    async fn activate(&self, l: &Value, d: &SigningKey) -> Value {
        let ch = self.challenge(l, d, "activate", None).await;
        let (status, result) = self
            .device("/v2/licenses/activate", self.proof(l, d, &ch))
            .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        result
    }
    async fn finish(self) {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.root)
            .await
            .unwrap();
        self.root.close().await;
    }
}
async fn request(
    router: &Router,
    method: Method,
    path: &str,
    value: Value,
    auth: Option<(&str, &str)>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some((cookie, csrf)) = auth {
        req = req.header("cookie", cookie).header("x-xsrf-token", csrf)
    }
    let response = router
        .clone()
        .oneshot(req.body(Body::from(value.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}
fn token_claims(v: &Value) -> Value {
    let token = v["token"].as_str().unwrap();
    let parts: Vec<_> = token.split('.').collect();
    let sig =
        ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    SigningKey::from_bytes(&[7; 32])
        .verifying_key()
        .verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap()
}

#[tokio::test]
async fn unauthenticated_or_missing_csrf_writes_fail_and_archival_blocks_new_contracts() {
    let h = Harness::new().await;
    let duplicate=h.router.clone().oneshot(Request::post("/admin/auth/login").header("content-type","application/json").body(Body::from(r#"{"username":"operator","username":"other","password":"integration-only-password"}"#)).unwrap()).await.unwrap();
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    let reused = h
        .call(
            Method::POST,
            "/admin/v2/applications",
            json!({"slug":"other-app","name":"Other","signingKeyId":"test-key"}),
        )
        .await;
    assert_eq!(reused.1["error"], "signing_key_conflict");
    let input = json!({"applicationId":h.app,"customer":{"name":"x","email":"a@b"},"expiresAt":Utc::now()+Duration::days(1)});
    assert_eq!(
        request(
            &h.router,
            Method::POST,
            "/admin/v2/licenses",
            input.clone(),
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &h.router,
            Method::POST,
            "/admin/v2/licenses",
            input,
            Some((&h.cookie, "wrong"))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.device("/v1/licenses/activate", json!({})).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.call(
            Method::POST,
            &format!("/admin/v2/applications/{}/archive", h.app),
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    let(status,_)=h.call(Method::POST,"/admin/v2/licenses",json!({"applicationId":h.app,"customer":{"name":"x","email":"a@b"},"expiresAt":Utc::now()+Duration::days(1)})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        h.call(Method::POST, "/admin/auth/logout", json!({}))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.call(Method::GET, "/admin/auth/me", Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
    h.finish().await;
}
#[tokio::test]
async fn concurrent_devices_only_bind_once_and_replay_cannot_change_request() {
    let h = Harness::new().await;
    let l = h.license().await;
    assert!(l["signedToken"].is_null());
    let a = SigningKey::from_bytes(&[1; 32]);
    let b = SigningKey::from_bytes(&[2; 32]);
    let ca = h.challenge(&l, &a, "activate", None).await;
    let cb = h.challenge(&l, &b, "activate", None).await;
    let pa = h.proof(&l, &a, &ca);
    let pb = h.proof(&l, &b, &cb);
    let (ra, rb) = tokio::join!(
        h.device("/v2/licenses/activate", pa.clone()),
        h.device("/v2/licenses/activate", pb.clone())
    );
    assert!(matches!(
        (ra.0, rb.0),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    let (proof, result, d) = if ra.0 == StatusCode::OK {
        (pa, ra.1, &a)
    } else {
        (pb, rb.1, &b)
    };
    assert_eq!(
        h.device("/v2/licenses/activate", proof.clone()).await.1,
        result
    );
    let mut changed = proof.clone();
    changed["idempotencyKey"] = json!(Uuid::new_v4());
    assert_eq!(
        h.device("/v2/licenses/activate", changed).await.1["error"],
        "idempotency_conflict"
    );
    let recovered = h.activate(&l, d).await;
    assert_eq!(recovered["token"], result["token"]);
    let claims = token_claims(&result);
    assert_eq!(claims["product_id"], h.app);
    assert_eq!(claims["revision"], 1);
    assert_eq!(claims["seat"], 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM device_bindings")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let ch = h.challenge(&l, d, "activate", None).await;
    let mut invalid = h.proof(&l, d, &ch);
    invalid["signature"] = json!(URL_SAFE_NO_PAD.encode([0; 64]));
    assert_eq!(
        h.device("/v2/licenses/activate", invalid).await.1["error"],
        "invalid_device_proof"
    );
    sqlx::query("UPDATE challenges SET expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(Uuid::parse_str(ch["challengeId"].as_str().unwrap()).unwrap())
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(
        h.device("/v2/licenses/activate", h.proof(&l, d, &ch))
            .await
            .1["error"],
        "challenge_expired"
    );
    let mut wrong = proof;
    wrong["productId"] = json!(Uuid::new_v4());
    assert_eq!(
        h.device("/v2/licenses/activate", wrong).await.1["error"],
        "invalid_activation_credentials"
    );
    h.finish().await;
}
#[tokio::test]
async fn renewal_is_atomic_revision_checked_and_requires_separate_sync_ack_proofs() {
    let h = Harness::new().await;
    let l = h.license().await;
    let d = SigningKey::from_bytes(&[1; 32]);
    let original = h.activate(&l, &d).await;
    let original_claims = token_claims(&original);
    let old_sync = h.challenge(&l, &d, "sync", None).await;
    let old_sync_proof = h.proof(&l, &d, &old_sync);
    let path = format!("/admin/v2/licenses/{}/renewals", l["id"].as_str().unwrap());
    let req = json!({"expectedRevision":1,"newExpiresAt":Utc::now()+Duration::days(60),"idempotencyKey":Uuid::new_v4(),"reason":"客户续约"});
    let mut rival = req.clone();
    rival["idempotencyKey"] = json!(Uuid::new_v4());
    let (a, b) = tokio::join!(
        h.call(Method::POST, &path, req.clone()),
        h.call(Method::POST, &path, rival.clone())
    );
    assert!(matches!(
        (a.0, b.0),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    let (winner, response) = if a.0 == StatusCode::OK {
        (req, a.1)
    } else {
        (rival, b.1)
    };
    assert_eq!(response["revision"], 2);
    assert_eq!(response["deliveryStatus"], "pending");
    assert_eq!(
        h.call(Method::POST, &path, winner.clone()).await.1,
        response
    );
    let mut altered = winner;
    altered["reason"] = json!("changed");
    assert_eq!(
        h.call(Method::POST, &path, altered).await.1["error"],
        "idempotency_conflict"
    );
    assert_eq!(
        h.device("/v2/licenses/sync", old_sync_proof).await.1["error"],
        "certificate_changed"
    );
    let sync = h.challenge(&l, &d, "sync", None).await;
    let proof = h.proof(&l, &d, &sync);
    let (status, new) = h.device("/v2/licenses/sync", proof.clone()).await;
    assert_eq!(status, StatusCode::OK, "{new}");
    let claims = token_claims(&new);
    assert_eq!(claims["revision"], 2);
    assert_eq!(
        claims["device_key_hash"],
        original_claims["device_key_hash"]
    );
    assert_eq!(claims["binding_version"], 1);
    let mut wrong_ack = proof;
    wrong_ack["serial"] = sync["serial"].clone();
    assert_eq!(
        h.device("/v2/licenses/acknowledgements", wrong_ack).await.0,
        StatusCode::UNAUTHORIZED
    );
    let ack = h.challenge(&l, &d, "ack", sync["serial"].as_str()).await;
    let mut ack_proof = h.proof(&l, &d, &ack);
    ack_proof["serial"] = ack["serial"].clone();
    assert_eq!(
        h.device("/v2/licenses/acknowledgements", ack_proof).await.0,
        StatusCode::OK
    );
    let detail_path = format!("/admin/v2/licenses/{}", l["id"].as_str().unwrap());
    assert_eq!(
        h.call(Method::GET, &detail_path, Value::Null).await.1["deliveryStatus"],
        "confirmed"
    );
    h.call(
        Method::POST,
        &format!("{detail_path}/revoke"),
        json!({"reason":"撤销"}),
    )
    .await;
    assert_eq!(
        h.device("/v2/licenses/sync", h.proof(&l, &d, &sync))
            .await
            .1["error"],
        "license_revoked"
    );
    let req = json!({"expectedRevision":2,"newExpiresAt":Utc::now()+Duration::days(90),"idempotencyKey":Uuid::new_v4(),"reason":"must fail"});
    assert_eq!(
        h.call(Method::POST, &path, req).await.1["error"],
        "license_revoked"
    );
    h.finish().await;
}
#[tokio::test]
async fn unavailable_signer_rolls_back_binding_and_contract_revision() {
    let h = Harness::new().await;
    let l = h.license().await;
    let d = SigningKey::from_bytes(&[1; 32]);
    let ch = h.challenge(&l, &d, "activate", None).await;
    let proof = h.proof(&l, &d, &ch);
    std::fs::rename(h.keys.path().join("seed"), h.keys.path().join("saved")).unwrap();
    assert_eq!(
        h.device("/v2/licenses/activate", proof.clone()).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM device_bindings")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    std::fs::rename(h.keys.path().join("saved"), h.keys.path().join("seed")).unwrap();
    assert_eq!(
        h.device("/v2/licenses/activate", proof).await.0,
        StatusCode::OK
    );
    std::fs::rename(h.keys.path().join("seed"), h.keys.path().join("saved")).unwrap();
    let path = format!("/admin/v2/licenses/{}/renewals", l["id"].as_str().unwrap());
    let req = json!({"expectedRevision":1,"newExpiresAt":Utc::now()+Duration::days(60),"idempotencyKey":Uuid::new_v4(),"reason":"rollback"});
    assert_eq!(
        h.call(Method::POST, &path, req).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM licenses")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(revision, 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM renewals")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    h.finish().await;
}

#[tokio::test]
async fn expired_unbound_contract_cannot_activate_until_admin_renews_exact_revision() {
    let h = Harness::new().await;
    let l = h.license().await;
    let d = SigningKey::from_bytes(&[1; 32]);
    let ch = h.challenge(&l, &d, "activate", None).await;
    let proof = h.proof(&l, &d, &ch);
    sqlx::query("UPDATE licenses SET expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(Uuid::parse_str(l["id"].as_str().unwrap()).unwrap())
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(
        h.device("/v2/licenses/activate", proof).await.1["error"],
        "license_expired"
    );
    let path = format!("/admin/v2/licenses/{}/renewals", l["id"].as_str().unwrap());
    let req = json!({"expectedRevision":1,"newExpiresAt":Utc::now()+Duration::days(60),"idempotencyKey":Uuid::new_v4(),"reason":"到期后续约"});
    let (status, renewed) = h.call(Method::POST, &path, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(renewed["revision"], 2);
    assert!(renewed["signedToken"].is_null());
    let activated = h.activate(&l, &d).await;
    assert_eq!(token_claims(&activated)["revision"], 2);
    let detail = h
        .call(
            Method::GET,
            &format!("/admin/v2/licenses/{}", l["id"].as_str().unwrap()),
            Value::Null,
        )
        .await
        .1;
    assert_eq!(detail["deliveryStatus"], "pending");
    assert!(!detail["renewals"][0]["serial"].is_null());
    h.finish().await;
}
