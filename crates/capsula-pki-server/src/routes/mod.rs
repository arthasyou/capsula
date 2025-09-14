use axum::Router;
use toolcraft_axum_kit::middleware::cors::create_cors;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::handlers::{ca, certificate, simple_ca};
use crate::models::{ca::*, certificate::*};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Capsula PKI Server API",
        version = "1.0.0",
        description = "Certificate Authority and PKI management API"
    ),
    paths(
        ca::get_ca_status,
        ca::get_ca_certificate,
        ca::initialize_ca,
        ca::health_check,
        certificate::create_certificate,
        certificate::get_certificate,
        certificate::list_certificates,
        certificate::revoke_certificate,
    ),
    components(
        schemas(
            CaInfo,
            CaInitRequest,
            CaStatus,
            CertificateRequest,
            CertificateResponse,
            CertificateStatus,
            RevocationRequest,
            RevocationReason,
            CertificateListQuery,
            CertificateListResponse,
        )
    ),
    tags(
        (name = "ca", description = "Certificate Authority management"),
        (name = "certificates", description = "Certificate management"),
        (name = "health", description = "Health check endpoints"),
    )
)]
struct ApiDoc;

pub fn create_routes() -> Router {
    let cors = create_cors();
    let doc = ApiDoc::openapi();

    Router::new()
        .merge(simple_ca::create_simple_router())
        .merge(ca::create_router())
        .merge(certificate::create_router())
        .layer(cors)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc))
}
