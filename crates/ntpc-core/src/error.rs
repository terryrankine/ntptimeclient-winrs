//! Errors returned by the ports.

use thiserror::Error;

/// A clock operation failed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ClockError {
    /// The process lacks the right to change the clock.
    #[error("permission denied")]
    PermissionDenied,
    /// The system refused the change.
    #[error("clock change rejected: {0}")]
    Rejected(String),
    /// The clock cannot be reached.
    #[error("clock unavailable")]
    Unavailable,
}

/// The drift store failed to save.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Reading or writing the store failed.
    #[error("drift store I/O failed: {0}")]
    Io(String),
}
