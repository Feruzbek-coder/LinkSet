use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Message(String),
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("System command failed: {0}")]
    Command(String),
    #[error("{0}")]
    PermissionDenied(String),
}

#[derive(Serialize)]
pub struct ErrorPayload {
    pub error_code: &'static str,
    pub message: String,
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ErrorPayload {
            error_code: match self {
                Self::Database(_) => "DATABASE_ERROR",
                Self::Command(_) => "SYSTEM_COMMAND_FAILED",
                Self::PermissionDenied(_) => "PERMISSION_DENIED",
                Self::Message(_) => "INVALID_REQUEST",
            },
            message: self.to_string(),
        }
        .serialize(serializer)
    }
}

pub type AppResult<T> = Result<T, AppError>;
