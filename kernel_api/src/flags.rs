//! Flags argument for each system call.

use bitflags::bitflags;

bitflags! {
    /// Flags for `spawn_thread`.
    pub struct SpawnThreadFlags: usize {

    }
}
