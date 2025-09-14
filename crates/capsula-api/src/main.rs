mod error;
mod handlers;
mod logging;
mod models;
mod routes;
mod settings;

use settings::Settings;
use toolcraft_axum_kit::http_server;

use crate::logging::init_tracing_to_file;

#[tokio::main]
async fn main() {
    // Use console logging for debugging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    
    let settings = Settings::load("config/services.toml").unwrap();

    // Initialize data capsule API server
    // TODO: Initialize key storage if needed
    
    let router = routes::create_routes();
    let http_task = http_server::start(settings.http.port, router);

    tracing::info!("Capsula API Server started on port {}", settings.http.port);
    let _ = tokio::join!(http_task);
}
