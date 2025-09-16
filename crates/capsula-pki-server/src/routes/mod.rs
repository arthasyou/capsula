mod ca;
mod certificate;
mod health;

use axum::Router;
use toolcraft_axum_kit::middleware::cors::create_cors;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::routes::{ca::CaApi, certificate::CertificateApi};

#[derive(OpenApi)]
#[openapi(
    nest(
        (path = "/ca", api = CaApi),
        (path = "/certificates", api = CertificateApi),
    ),
)]
struct ApiDoc;

pub fn create_routes() -> Router {
    let cors = create_cors();
    let doc = ApiDoc::openapi();

    Router::new()
        // .merge(create_health_router())
        .nest("/ca", ca::create_router())
        .nest("/certificates", certificate::create_router())
        .layer(cors)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc))
}
