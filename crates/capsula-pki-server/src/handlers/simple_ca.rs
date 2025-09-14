use axum::{http::StatusCode, response::Json, routing::get, Router};
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

pub fn create_simple_router() -> Router {
    Router::new()
        .route("/simple-health", get(health))
        .route("/simple-ca-status", get(ca_status))
}