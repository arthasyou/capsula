mod health;

use axum::Router;
use toolcraft_axum_kit::middleware::cors::create_cors;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::routes::health::HealthApi;

#[derive(OpenApi)]
#[openapi(
    nest(
         (path = "/health", api = HealthApi),
    ),
    paths(crate::handlers::health::health, crate::handlers::health::ca_status,)
)]
struct ApiDoc;

pub fn create_routes() -> Router {
    let cors = create_cors();
    let doc = ApiDoc::openapi();

    Router::new()
        .nest("/health", health::create_router())
        .layer(cors)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc))
}
