use axum::{
    routing::{get, post},
    Router,
};
use utoipa::OpenApi;

use crate::handlers::ca::{get_ca_certificate, get_ca_status, health_check, initialize_ca};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::ca::get_ca_status,
        crate::handlers::ca::get_ca_certificate,
        crate::handlers::ca::initialize_ca,
        crate::handlers::ca::health_check,
    ),
    tags(
        (name = "CA", description = "Certificate Authority APIs")
    ),
)]

pub struct CaApi;

pub fn create_router() -> Router {
    Router::new()
        .route("/status", get(get_ca_status))
        .route("/certificate", get(get_ca_certificate))
        .route("/initialize", post(initialize_ca))
        .route("/health", get(health_check))
}
