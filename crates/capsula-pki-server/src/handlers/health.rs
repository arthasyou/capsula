use axum::response::Json;
use serde_json::json;

pub async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "capsula-pki-server"
    }))
}

pub async fn ca_status() -> Json<serde_json::Value> {
    Json(json!({
        "initialized": false,
        "message": "Simple PKI server working"
    }))
}
