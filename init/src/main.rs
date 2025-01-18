//! The Cavern `init` process.
//!
//! The `init` process is responsible for starting up user space.
#![no_std]
#![no_main]
#![deny(missing_docs)]
#![allow(clippy::cast_possible_truncation)]

use kernel_api::{
    ThreadCreateInfo, allocate_heap_pages, exit_current_thread, free_heap_pages, spawn_thread,
};

fn thread2(arg: usize) -> ! {
    let thread_id = kernel_api::read_env_value(kernel_api::EnvironmentValue::CurrentThreadId);
    exit_current_thread((thread_id + 1 + arg) as u32);
}

/// The main entry point.
///
/// # Panics
/// Right now we panic if any errors happen.
#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let process_id = kernel_api::read_env_value(kernel_api::EnvironmentValue::CurrentProcessId);

    spawn_thread(&ThreadCreateInfo {
        entry: thread2,
        stack_size: 1,
        user_data: 7000,
    })
    .expect("spawn thread");

    let p = allocate_heap_pages(1).expect("allocate");
    unsafe {
        p.write(0xab);
    }
    free_heap_pages(p, 1).expect("free");

    exit_current_thread((process_id + 1) as u32);
}

/// The panic handler.
#[panic_handler]
pub fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    exit_current_thread(1);
}
