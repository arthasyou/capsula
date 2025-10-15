// Legacy modules for backward compatibility (no version prefix)
mod authorization;
mod capsule;

// Versioned API modules
pub mod v1;
pub mod v2;

use axum::Router;
use toolcraft_axum_kit::middleware::cors::create_cors;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::routes::{authorization::AuthorizationApi, capsule::CapsuleApi, v1::V1Api, v2::V2Api};

/// Legacy API documentation (no version prefix)
#[derive(OpenApi)]
#[openapi(
    nest(
         (path = "/capsule", api = CapsuleApi),
         (path = "/auth", api = AuthorizationApi),
    ),
)]
struct LegacyApiDoc;

/// V1 API documentation
#[derive(OpenApi)]
#[openapi(
    nest(
         (path = "/v1", api = V1Api),
    ),
)]
struct V1ApiDoc;

/// V2 API documentation
#[derive(OpenApi)]
#[openapi(
    nest(
         (path = "/v2", api = V2Api),
    ),
)]
struct V2ApiDoc;

/// Combined API documentation
#[derive(OpenApi)]
#[openapi(
    nest(
        //  (path = "/", api = LegacyApiDoc),
         (path = "/v1", api = V1Api),
         (path = "/v2", api = V2Api),
    ),
)]
struct ApiDoc;

pub fn create_routes() -> Router {
    let cors = create_cors();
    let doc = ApiDoc::openapi();

    Router::new()
        // Legacy routes (no version prefix) - backward compatibility
        // .nest("/capsule", capsule::create_router())
        // .nest("/auth", authorization::create_router())
        // V1 routes (explicit version)
        .nest("/v1", v1::create_router())
        // V2 routes (new features)
        .nest("/v2", v2::create_router())
        .layer(cors)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc))
}
