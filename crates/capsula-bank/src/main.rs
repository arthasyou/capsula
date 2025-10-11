use capsula_bank::{
    db::{create_tables, init_db},
    logging::init_tracing_to_file,
    routes,
    settings::Settings,
    static_files::key,
};
use toolcraft_axum_kit::http_server;

#[tokio::main]
async fn main() {
    init_tracing_to_file();
    let settings = Settings::load("config/services.toml").unwrap();

    // Initialize system RSA key - MUST succeed or server won't start
    tracing::info!(
        "Initializing system RSA key from: {}",
        settings.key.private_key_path
    );
    key::init_system_key(&settings.key.private_key_path).unwrap_or_else(|e| {
        tracing::error!("Failed to initialize system RSA key: {}", e);
        tracing::error!("Server cannot start without system RSA key. Exiting.");
        std::process::exit(1);
    });
    tracing::info!("System RSA key initialized successfully");

    // Initialize database for certificate storage
    tracing::info!("Initializing database connection...");
    match init_db(settings.surrealdb).await {
        Ok(()) => {
            create_tables().await.unwrap();
            tracing::info!("Database initialized successfully");
        }
        Err(e) => {
            tracing::warn!(
                "Database initialization failed: {}. Continuing without database.",
                e
            );
            tracing::warn!("Some features may not work without database connection");
        }
    }

    let router = routes::create_routes();
    let http_task = http_server::start(settings.http.port, router);

    let _ = tokio::join!(http_task);
}
