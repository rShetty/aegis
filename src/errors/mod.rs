use thiserror::Error;

#[derive(Debug, Error)]
pub enum AegisError {
    #[error("egress blocked: {0}")]
    EgressBlocked(String),

    #[error("attestation failed: {0}")]
    AttestationFailed(String),

    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AegisError>;

impl From<rusqlite::Error> for AegisError {
    fn from(e: rusqlite::Error) -> Self {
        AegisError::Database(e.to_string())
    }
}

impl IntoResponse for AegisError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AegisError::EgressBlocked(_) => (StatusCode::FORBIDDEN, self.to_string()),
            AegisError::AttestationFailed(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AegisError::PolicyNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AegisError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AegisError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
