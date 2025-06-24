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
    /// Flags for the `driver_acquire_address_region()` system call.
    #[derive(Debug, Clone, Copy)]
    pub struct DriverAddressRegionFlags: usize {
        /// Enables caching for the mapped region.
        const ENABLE_CACHE = 0b01;
        /// Map the region read-only.
        const READ_ONLY = 0b10;
    }
}

bitflags! {
    /// Flags that define the properties of a shared buffer.
    #[derive(Debug, Clone, Copy)]
    pub struct SharedBufferFlags: u32 {
        /// Allows the borrower to read from the buffer.
        const READ = 0b01;
        /// Allows the borrower to write to the buffer.
        const WRITE = 0b10;
    }
}

bitflags! {
    /// Flags for the `free_message()` system call.
    #[derive(Debug, Clone, Copy)]
    pub struct FreeMessageFlags: usize {
        /// If set, frees all shared buffers attached to this message that are not already freed.
        const FREE_BUFFERS = 0b1;
    }
}

bitflags! {
    /// Flags for the `exit_notification_subscription()` system call.
    #[derive(Debug, Clone, Copy)]
    pub struct ExitNotificationSubscriptionFlags: usize {
        /// The ID parameter is a process. Mutex with `THREAD`.
        const PROCESS = 0b001;
        /// The ID parameter is a thread. Mutex with `PROCESS`.
        const THREAD = 0b010;
        /// Unsubscribes the current process if it was already subscribed.
        const UNSUBSCRIBE = 0b100;
    }
}
