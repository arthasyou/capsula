mod authorization;
mod capsule;

use axum::Router;
use toolcraft_axum_kit::middleware::cors::create_cors;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::routes::{authorization::AuthorizationApi, capsule::CapsuleApi};

#[derive(OpenApi)]
#[openapi(
    nest(
         (path = "/capsule", api = CapsuleApi),
         (path = "/auth", api = AuthorizationApi),
    ),
)]
struct ApiDoc;

pub fn create_routes() -> Router {
    let cors = create_cors();
    let doc = ApiDoc::openapi();

    Router::new()
        .nest("/capsule", capsule::create_router())
        .nest("/auth", authorization::create_router())
        .layer(cors)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc))
}
