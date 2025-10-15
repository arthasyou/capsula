use axum::{routing::post, Router};
use utoipa::OpenApi;

use crate::handlers::v2::capsule::upload_and_create_capsule;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::v2::capsule::upload_and_create_capsule,
    ),
    tags(
        (name = "Capsule V2", description = "Advanced capsule management APIs with file upload support")
    ),
)]
pub struct CapsuleV2Api;

pub fn create_router() -> Router {
    Router::new().route("/upload", post(upload_and_create_capsule))
}
