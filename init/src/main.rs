//! The Cavern `init` process.
//!
//! The `init` process is responsible for starting up user space.
#![no_std]
#![no_main]
#![deny(missing_docs)]

use kernel_api::exit_current_thread;

/// The main entry point.
#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let process_id = kernel_api::read_env_value(kernel_api::EnvironmentValue::CurrentProcessId);

    exit_current_thread((process_id + 1) as u32);
}

/// The panic handler.
#[panic_handler]
pub fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    exit_current_thread(1);
}
