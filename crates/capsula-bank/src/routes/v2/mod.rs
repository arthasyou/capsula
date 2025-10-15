mod capsule;

use axum::Router;
use utoipa::OpenApi;

pub use capsule::CapsuleV2Api;

#[derive(OpenApi)]
#[openapi(
    nest(
         (path = "/capsule", api = CapsuleV2Api),
    ),
)]
pub struct V2Api;

pub fn create_router() -> Router {
    Router::new().nest("/capsule", capsule::create_router())
}
