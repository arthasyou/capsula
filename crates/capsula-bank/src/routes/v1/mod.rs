mod authorization;
mod capsule;

pub use authorization::AuthorizationApi;
use axum::Router;
pub use capsule::CapsuleApi;
use utoipa::OpenApi;

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
