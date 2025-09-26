use axum::{
    routing::{get, post},
    Router,
};
use utoipa::OpenApi;

use crate::handlers::capsule::{
    create_capsule, get_capsule_by_id, get_capsules_by_owner, search_capsules,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::capsule::create_capsule,
        crate::handlers::capsule::get_capsule_by_id,
        crate::handlers::capsule::get_capsules_by_owner,
        crate::handlers::capsule::search_capsules,
    ),
    tags(
        (name = "Capsule", description = "Capsule management APIs")
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
