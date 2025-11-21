#[derive(Debug, thiserror::Error)]
pub enum BashtionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Static analysis blocked: {0}")]
    StaticBlocked(String),
    #[error("Static analysis caution: {0}")]
    StaticCaution(String),
    #[error("Semantic analysis blocked: {0}")]
    SemanticBlocked(String),
    #[error("Semantic analysis failed: {0}")]
    SemanticError(String),
    #[error("Other error: {0}")]
    Other(String),
}
