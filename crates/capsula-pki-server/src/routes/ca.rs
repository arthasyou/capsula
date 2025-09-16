use axum::{
    routing::get,
    Router,
};
use utoipa::OpenApi;

use crate::{handlers::ca::{get_ca_certificate, get_ca_status, get_root_ca, get_intermediate_ca}, state::AppState};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::ca::get_ca_status,
        crate::handlers::ca::get_ca_certificate,
        crate::handlers::ca::get_root_ca,
        crate::handlers::ca::get_intermediate_ca,
    ),
    tags(
        (name = "CA", description = "Certificate Authority APIs")
    ),
)]

pub struct CaApi;

pub fn create_router() -> Router<AppState> {
    Router::new()
        .route("/status", get(get_ca_status))
        .route("/certificate", get(get_ca_certificate))
        .route("/root", get(get_root_ca))
        .route("/intermediate", get(get_intermediate_ca))
}
