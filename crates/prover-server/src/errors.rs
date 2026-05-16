//! HTTP-boundary error types.
//!
//! Failures at the server's edge fall into a small number of
//! shapes: malformed JSON, malformed wire-form inputs (caught by
//! the circuit crate's `InputsError`), prover-internal errors
//! (synthesis, serialization), and PK/VK lookup failures. Each
//! gets mapped to an HTTP status code in the `IntoResponse` impl.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// The server's top-level error type. Anything a handler returns
/// via `?` lands here.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The path's `<circuit-id>` doesn't match any registered
    /// circuit. 404.
    #[error("unknown circuit: {0}")]
    UnknownCircuit(String),

    /// The request body's wire-form `Inputs` failed validation
    /// at the circuit crate. 400 with the underlying error
    /// message.
    #[error("invalid inputs: {0}")]
    BadInputs(#[from] circuits::pedersen_opens_to::InputsError),

    /// The proof bytes in a verify request failed to decode.
    /// 400.
    #[error("invalid proof bytes: {0}")]
    BadProofBytes(String),

    /// A prover-internal error: synthesis, serialization, etc.
    /// 500 — these shouldn't happen in production, and if they
    /// do they're our bugs, not the caller's.
    #[error("prover error: {0}")]
    Prover(#[from] prover::ProverError),

    /// Anything else that's our fault — file I/O, etc. 500.
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ServerError::UnknownCircuit(_) => (StatusCode::NOT_FOUND, self.to_string()),
            ServerError::BadInputs(_) | ServerError::BadProofBytes(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            ServerError::Prover(_) | ServerError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        let body = Json(serde_json::json!({ "error": message }));
        (status, body).into_response()
    }
}

pub type ServerResult<T> = Result<T, ServerError>;
