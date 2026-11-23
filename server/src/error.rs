use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub struct Error(pub StatusCode, pub &'static str);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(ref d) = e {
            if d.is_unique_violation() {
                return conflict("conflict");
            }
        }
        tracing::error!(error=%e,"database operation failed");
        Error(StatusCode::INTERNAL_SERVER_ERROR, "storage_error")
    }
}
pub fn bad(code: &'static str) -> Error {
    Error(StatusCode::BAD_REQUEST, code)
}
pub fn conflict(code: &'static str) -> Error {
    Error(StatusCode::CONFLICT, code)
}
pub fn unauthorized() -> Error {
    Error(StatusCode::UNAUTHORIZED, "invalid_activation_credentials")
}
pub fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(bad("invalid_request"))
}
pub fn uuid(v: &Value, k: &str) -> Result<uuid::Uuid> {
    uuid::Uuid::parse_str(field(v, k)?).map_err(|_| bad("invalid_request"))
}
pub fn time(v: &Value, k: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    let t = chrono::DateTime::parse_from_rfc3339(field(v, k)?)
        .map_err(|_| bad("invalid_expiry"))?
        .with_timezone(&chrono::Utc);
    if t.timestamp() < 0 || t.timestamp() > 9_007_199_254_740_991 {
        return Err(bad("invalid_expiry"));
    }
    Ok(chrono::DateTime::from_timestamp(t.timestamp(), 0).unwrap())
}
