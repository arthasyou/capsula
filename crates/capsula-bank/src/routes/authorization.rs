use axum::{
    routing::{get, post},
    Router,
};
use utoipa::OpenApi;

use crate::handlers::authorization::{
    grant_permission, list_permissions, revoke_permission, use_token,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::authorization::grant_permission,
        crate::handlers::authorization::use_token,
        crate::handlers::authorization::revoke_permission,
        crate::handlers::authorization::list_permissions,
    ),
    tags(
        (name = "Authorization", description = "Token and permission management APIs")
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
