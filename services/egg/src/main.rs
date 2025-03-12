//! The "egg" bootstrap service is the first spawned process and starts the rest of the system.
//! This requires it to have a few somewhat disjoint responsibilities:
//! - providing a service to interact with the initial RAM disk passed from the kernel as a file system
//! - spawning the root resource registry process, root supervisor process and log redistributor
//! - starting various core drivers based on the device tree blob passed from the kernel
//! - spawning the supervisors for the rest of user space
#![no_std]
#![no_main]
#![deny(missing_docs)]
#![allow(clippy::cast_possible_truncation)]

use kernel_api::{exit_current_thread, write_log};

/// The main entry point.
///
/// # Panics
/// Right now we panic if any errors happen.
#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    write_log(3, "egg boot start").unwrap();

    exit_current_thread(0);
}

/// The panic handler.
#[panic_handler]
pub fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    let _ = write_log(1, "panic!");
    exit_current_thread(1);
}
