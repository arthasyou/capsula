mod capsule;
mod storage;

use axum::Router;
use utoipa::OpenApi;

pub use capsule::CapsuleV2Api;
pub use storage::StorageV2Api;

#[derive(OpenApi)]
#[openapi(
    nest(
         (path = "/capsule", api = CapsuleV2Api),
         (path = "/storage", api = StorageV2Api),
    ),
)]
pub struct V2Api;

pub fn create_router() -> Router {
    Router::new()
        .nest("/capsule", capsule::create_router())
        .nest("/storage", storage::create_router())
}
