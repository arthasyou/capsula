mod db;
mod error;
mod handlers;
mod logging;
mod models;
mod routes;
mod settings;

use settings::Settings;
use toolcraft_axum_kit::http_server;

use crate::{
    db::{create_tables, init_db},
    logging::init_tracing_to_file,
};

#[tokio::main]
async fn main() {
    init_tracing_to_file();
    let settings = Settings::load("config/services.toml").unwrap();

    // Initialize database
    init_db(settings.surrealdb).await.unwrap();
    create_tables().await.unwrap();

    // Initialize PKI CA if needed
    // TODO: Initialize Certificate Authority and key storage

    let router = routes::create_routes();
    let http_task = http_server::start(settings.http.port, router);

    tracing::info!("PKI Server started on port {}", settings.http.port);
    let _ = tokio::join!(http_task);
}
