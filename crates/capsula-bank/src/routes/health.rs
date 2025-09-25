use axum::{routing::get, Router};
use utoipa::OpenApi;

use crate::handlers::health::{ca_status, health};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::health::health,
        crate::handlers::health::ca_status,
    ),
    tags(
        (name = "Health", description = "Health APIs")
    ),
)]
pub struct HealthApi;

pub fn create_router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(ca_status))
}
