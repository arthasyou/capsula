use axum::{
    routing::{get, post},
    Router,
};
use utoipa::OpenApi;

use crate::handlers::certificate::{
    create_certificate, get_certificate, list_certificates, revoke_certificate,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::certificate::create_certificate,
        crate::handlers::certificate::get_certificate,
        crate::handlers::certificate::list_certificates,
        crate::handlers::certificate::revoke_certificate,
    ),
    tags(
        (name = "Certificate", description = "Certificate APIs")
    ),
)]

pub struct CertificateApi;

pub fn create_router() -> Router {
    Router::new()
        .route("/create", post(create_certificate))
        .route("/get/{certificate_id}", get(get_certificate))
        .route("/list", get(list_certificates))
        .route("/revoke/{certificate_id}", post(revoke_certificate))
}
