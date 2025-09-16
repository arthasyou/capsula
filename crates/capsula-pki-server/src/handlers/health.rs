use axum::response::Json;
use serde_json::json;

/// Health check endpoint
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service is healthy"),
    ),
    tag = "Health"
)]
pub async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "capsula-pki-server"
    }))
}

/// Service status endpoint
#[utoipa::path(
    get,
    path = "/status",
    responses(
        (status = 200, description = "Service status information"),
    ),
    tag = "Health"
)]
pub async fn ca_status() -> Json<serde_json::Value> {
    Json(json!({
        "initialized": false,
        "message": "Simple PKI server working"
    }))
}
