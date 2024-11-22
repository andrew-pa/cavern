//! Threads
use alloc::sync::Arc;
#[cfg(test)]
use mockall::automock;

/// A single thread of execution in a user-space process.
pub struct Thread {}

/// Abstract scheduler policy
#[cfg_attr(test, automock)]
pub trait Scheduler: Sync {
    /// Get the currently running thread.
    fn current_thread(&self) -> Arc<Thread>;

    /// Update the thread scheduler for a new time slice,
    /// potentially updating the currently running thread.
    fn next_time_slice(&self);
}

/// Abstract thread switching mechanism
#[cfg_attr(test, automock)]
pub trait Switcher {
    /// Save the current EL0 thread state into `thread`.
    unsafe fn save_thread_state(thread: &Thread);

    /// Restore the state of `thread` into the current EL0 thread state.
    unsafe fn restore_thread_state(thread: &Thread);
}
