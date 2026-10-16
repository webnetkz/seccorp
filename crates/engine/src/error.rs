use std::path::PathBuf;

/// Engine error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("I/O error on {path}: {source}")]
    IoPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("signature database error: {0}")]
    Database(String),

    #[error("rule error ({location}): {message}")]
    Rule { location: String, message: String },

    #[error("pattern error: {0}")]
    Pattern(String),

    #[error("quarantine error: {0}")]
    Quarantine(String),

    #[error("update error: {0}")]
    Update(String),

    #[error("signature verification failed: {0}")]
    Signature(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("operation cancelled")]
    Cancelled,

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn io_path(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::IoPath { path: path.into(), source }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
