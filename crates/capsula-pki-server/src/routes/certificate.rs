use axum::{
    routing::{get, post},
    Router,
};
use utoipa::OpenApi;

use crate::{
    handlers::certificate::{
        create_certificate, get_certificate, get_user_certificates, list_certificates,
        renew_certificate, revoke_certificate,
    },
    state::AppState,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::certificate::create_certificate,
        crate::handlers::certificate::get_certificate,
        crate::handlers::certificate::list_certificates,
        crate::handlers::certificate::renew_certificate,
        crate::handlers::certificate::revoke_certificate,
        crate::handlers::certificate::get_user_certificates,
    ),
    tags(
        (name = "Certificate", description = "Certificate APIs")
    ),
)]

pub struct CertificateApi;

pub fn create_router() -> Router<AppState> {
    Router::new()
        .route("/create", post(create_certificate))
        .route("/get/{certificate_id}", get(get_certificate))
        .route("/list", get(list_certificates))
        .route("/renew", post(renew_certificate))
        .route("/revoke/{certificate_id}", post(revoke_certificate))
        .route("/users/{user_id}/certificates", get(get_user_certificates))
}
