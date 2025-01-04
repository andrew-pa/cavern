//! Flags argument for each system call.

use bitflags::bitflags;

bitflags! {
    /// Flags for `spawn_thread`.
    pub struct SpawnThreadFlags: usize {

    }
}

bitflags! {
    /// Flags for `spawn_process`.
    pub struct SpawnProcessFlags: usize {
        /// Disables the kernel-sent message to the parent (current) process when the spawned
        /// process exits.
        const IGNORE_EXIT = 0b1;
    }
}
