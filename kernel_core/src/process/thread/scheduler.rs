//! Thread scheduler implementation.
use super::{Scheduler, Thread};
use alloc::sync::Arc;

/// A round-robin scheduler.
pub struct RoundRobinScheduler {}

impl Default for RoundRobinScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundRobinScheduler {
    /// Create a new scheduler.
    #[must_use]
    pub fn new() -> Self {
        RoundRobinScheduler {}
    }
}

impl Scheduler for RoundRobinScheduler {
    fn current_thread(&self) -> Arc<Thread> {
        todo!()
    }

    fn next_time_slice(&self) {
        todo!()
    }
}
