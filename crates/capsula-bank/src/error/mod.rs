pub mod error_code;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum AppError {
    #[error("config error: {0}")]
    #[allow(clippy::enum_variant_names)]
    ConfigError(#[from] toolcraft_config::error::Error),

    #[error("validation error: {0}")]
    #[allow(clippy::enum_variant_names)]
    ValidationError(#[from] validator::ValidationErrors),

    #[error("db error: {0}")]
    DbError(#[from] surrealdb::Error),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::ConfigError(ref e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::ValidationError(ref e) => (StatusCode::BAD_REQUEST, e.to_string()),
            AppError::IoError(ref e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::NotFound(ref e) => (StatusCode::NOT_FOUND, e.to_string()),
            AppError::BadRequest(ref e) => (StatusCode::BAD_REQUEST, e.to_string()),
            AppError::Internal(ref e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::DbError(ref e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

pub type Result<T, E = AppError> = core::result::Result<T, E>;
