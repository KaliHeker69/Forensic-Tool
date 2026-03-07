//! Error types for vol3-correlate

use thiserror::Error;

/// Main error type for the application
#[derive(Error, Debug)]
pub enum Vol3Error {
    #[error("Failed to read file: {path}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse JSON: {path}")]
    JsonParse {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Unknown plugin type for file: {path}")]
    UnknownPlugin { path: String },

    #[error("Missing required column: {column} in {path}")]
    MissingColumn { column: String, path: String },

    #[error("Invalid timestamp format: {value}")]
    InvalidTimestamp { value: String },

    #[error("Template rendering failed: {0}")]
    Template(#[from] tera::Error),

    #[error("Polars error: {0}")]
    Polars(#[from] polars::error::PolarsError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("No input files found in directory: {path}")]
    NoInputFiles { path: String },

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Vol3Error>;
