use axum::{
    routing::{get, post},
    Router,
};
use utoipa::OpenApi;

use crate::handlers::v1::capsule::{
    create_capsule, get_capsule_by_id, get_capsules_by_owner, search_capsules,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::v1::capsule::create_capsule,
        crate::handlers::v1::capsule::get_capsule_by_id,
        crate::handlers::v1::capsule::get_capsules_by_owner,
        crate::handlers::v1::capsule::search_capsules,
    ),
    tags(
        (name = "Capsule", description = "Capsule management APIs (V1)")
    ),
)]
pub struct CapsuleApi;

pub fn create_router() -> Router {
    Router::new()
        .route("/", post(create_capsule))
        .route("/{id}", get(get_capsule_by_id))
        .route("/owner/{owner_id}", get(get_capsules_by_owner))
        .route("/search", get(search_capsules))
}
