use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Key error: {0}")]
    Key(#[from] capsula_key::error::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("File not found: {0}")]
    FileNotFound(String),
    
    #[error("Other error: {0}")]
    Other(String),
}

pub type CliResult<T> = Result<T, CliError>;