#[derive(Debug, thiserror::Error)]
pub enum BashtionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Semantic analysis failed: {0}")]
    SemanticError(String),
    #[error("Other error: {0}")]
    Other(String),
}
