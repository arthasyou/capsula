use axum::Router;
use toolcraft_axum_kit::middleware::cors::create_cors;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::handlers::capsule;
use crate::models::capsule::*;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Capsula Data Capsule API",
        version = "1.0.0",
        description = "Data encapsulation and decapsulation API using Capsula protocol"
    ),
    paths(
        capsule::encapsulate_data,
        capsule::decapsulate_data,
        capsule::verify_capsule,
    ),
    components(
        schemas(
            EncapsulateRequest,
            EncapsulateResponse,
            DecapsulateRequest,
            DecapsulateResponse,
            CapsuleVerifyRequest,
            CapsuleVerifyResponse,
        )
    ),
    tags(
        (name = "capsule", description = "Data capsule operations"),
    )
)]
struct ApiDoc;

pub fn create_routes() -> Router {
    let cors = create_cors();
    let doc = ApiDoc::openapi();

    Router::new()
        .merge(capsule::create_router())
        .layer(cors)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc))
}
