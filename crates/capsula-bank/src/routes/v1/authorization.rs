use axum::{
    routing::{get, post},
    Router,
};
use utoipa::OpenApi;

use crate::handlers::v1::authorization::{
    grant_permission, list_permissions, revoke_permission, use_token,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::v1::authorization::grant_permission,
        crate::handlers::v1::authorization::use_token,
        crate::handlers::v1::authorization::revoke_permission,
        crate::handlers::v1::authorization::list_permissions,
    ),
    tags(
        (name = "Authorization", description = "Token and permission management APIs (V1)")
    ),
)]
pub struct AuthorizationApi;

pub fn create_router() -> Router {
    Router::new()
        .route("/grant", post(grant_permission))
        .route("/use", post(use_token))
        .route("/revoke", post(revoke_permission))
        .route("/list", get(list_permissions))
}
