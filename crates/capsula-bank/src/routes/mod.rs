// Versioned API modules
pub mod v1;
pub mod v2;

use axum::Router;
use toolcraft_axum_kit::middleware::cors::create_cors;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::routes::{v1::V1Api, v2::V2Api};

/// Combined API documentation
#[derive(OpenApi)]
#[openapi(
    nest(
         (path = "/v1", api = V1Api),
         (path = "/v2", api = V2Api),
    ),
)]
struct ApiDoc;

pub fn create_routes() -> Router {
    let cors = create_cors();
    let doc = ApiDoc::openapi();

    Router::new()
        .nest("/v1", v1::create_router())
        .nest("/v2", v2::create_router())
        .layer(cors)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc))
}
