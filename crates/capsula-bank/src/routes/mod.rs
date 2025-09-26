mod capsule;

use axum::Router;
use toolcraft_axum_kit::middleware::cors::create_cors;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::routes::capsule::CapsuleApi;

#[derive(OpenApi)]
#[openapi(
    nest(
         (path = "/capsule", api = CapsuleApi),
    ),
    paths(
        crate::handlers::capsule::create_capsule,
        crate::handlers::capsule::get_capsule_by_id,
        crate::handlers::capsule::get_capsules_by_owner,
        crate::handlers::capsule::search_capsules,
    )
)]
struct ApiDoc;

pub fn create_routes() -> Router {
    let cors = create_cors();
    let doc = ApiDoc::openapi();

    Router::new()
        .nest("/capsule", capsule::create_router())
        .layer(cors)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc))
}
