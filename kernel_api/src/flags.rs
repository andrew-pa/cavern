//! Flags argument for each system call.

use bitflags::bitflags;

bitflags! {
    /// Flags for the `receive()` system call.
    #[derive(Debug, Clone, Copy)]
    pub struct ReceiveFlags: usize {
        /// Immediately return with a [`crate::ErrorCode::WouldBlock`] error if there are no
        /// messages instead of blocking the thread until a message arrives.
        const NONBLOCKING = 0b1;
    }
}

bitflags! {
    /// Flags that define the properties of a shared buffer.
    #[derive(Debug, Clone, Copy)]
    pub struct SharedBufferFlags: usize {
        /// Allows the borrower to read from the buffer.
        const READ = 0b1;
        /// Allows the borrower to write to the buffer.
        const WRITE = 0b1;
    }
}
