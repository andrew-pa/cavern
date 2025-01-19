//! Flags argument for each system call.

use bitflags::bitflags;

bitflags! {
    /// Flags for the `receive()` system call.
    pub struct ReceiveFlags: usize {
        /// Immediately return with a [`crate::ErrorCode::WouldBlock`] error if there are no
        /// messages instead of blocking the thread until a message arrives.
        const NONBLOCKING = 0b1;
    }
}
