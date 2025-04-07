//! Interfaces for various core user space services.

use kernel_api::ErrorCode;
use snafu::Snafu;

pub mod registry;

/// Errors that can take place making RPC calls via a client in this module.
#[derive(Debug, Snafu)]
pub enum Error {
    /// A message send failed.
    Send {
        /// The underlying error code from the kernel.
        source: ErrorCode,
    },
    /// The service returned a [`ResponseType::InvalidPayloadFormat`].
    InvalidPayloadFormat,
    /// The service returned a [`ResponseType::InternalError`].
    Internal,
}
