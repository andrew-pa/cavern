//! The Cavern `init` process.
//!
//! The `init` process is responsible for starting up user space.
#![no_std]
#![no_main]
#![deny(missing_docs)]

use kernel_api::{ThreadCreateInfo, exit_current_thread, flags::SpawnThreadFlags, spawn_thread};

fn thread2(arg: usize) -> ! {
    let thread_id = kernel_api::read_env_value(kernel_api::EnvironmentValue::CurrentThreadId);
    exit_current_thread((thread_id + 1 + arg) as u32);
}

/// The main entry point.
#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let process_id = kernel_api::read_env_value(kernel_api::EnvironmentValue::CurrentProcessId);

    spawn_thread(SpawnThreadFlags::empty(), &ThreadCreateInfo {
        entry: thread2,
        stack_size: 1,
        inbox_size: 0,
        user_data: 7000,
    })
    .expect("spawn thread");

    exit_current_thread((process_id + 1) as u32);
}

/// The panic handler.
#[panic_handler]
pub fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    exit_current_thread(1);
}
