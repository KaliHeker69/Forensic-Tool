use thiserror::Error;

#[derive(Error, Debug)]
pub enum PrefetchError {
    #[error("Parse error: {0}")]
    ParseError(String),
}
