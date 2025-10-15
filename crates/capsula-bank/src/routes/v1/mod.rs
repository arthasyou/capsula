mod authorization;
mod capsule;

use axum::Router;
use utoipa::OpenApi;

pub use authorization::AuthorizationApi;
pub use capsule::CapsuleApi;

#[derive(OpenApi)]
#[openapi(
    nest(
         (path = "/capsule", api = CapsuleApi),
         (path = "/auth", api = AuthorizationApi),
    ),
)]
pub struct V1Api;

pub fn create_router() -> Router {
    Router::new()
        .nest("/capsule", capsule::create_router())
        .nest("/auth", authorization::create_router())
}
