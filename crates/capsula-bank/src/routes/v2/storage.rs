use axum::{routing::post, Router};
use utoipa::OpenApi;

use crate::handlers::v2::storage::generate_presigned_url;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::v2::storage::generate_presigned_url,
    ),
    tags(
        (name = "Storage V2", description = "Storage helper APIs for presigned URL generation")
    ),
)]
pub struct StorageV2Api;

pub fn create_router() -> Router {
    Router::new().route("/presigned-url", post(generate_presigned_url))
}
