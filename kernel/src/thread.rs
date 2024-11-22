//! Thread switching mechanism.

use kernel_core::process::thread::{Switcher, Thread};

/// A real thread switcher that reads/writes system registers.
pub struct RealSwitcher;

impl Switcher for RealSwitcher {
    unsafe fn save_thread_state(thread: &Thread) {
        todo!()
    }

    unsafe fn restore_thread_state(thread: &Thread) {
        todo!()
    }
}
