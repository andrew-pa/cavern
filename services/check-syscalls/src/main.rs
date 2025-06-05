//! A quick test to make sure that system calls operate as expected.
#![no_std]
#![no_main]
#![allow(clippy::cast_possible_truncation)]

extern crate alloc;
use alloc::format;
use kernel_api::{exit_current_thread, write_log};

#[global_allocator]
static ALLOCATOR: user_core::heap::GlobalAllocator = user_core::heap::init_allocator();

/// Trait to enable nice test logs (by giving access to the name of the function).
pub trait Testable {
    /// Execute the test.
    fn run(&self);
}

impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        write_log(4, &format!("running {}...", core::any::type_name::<T>())).unwrap();
        self();
        write_log(3, &format!("{} ok", core::any::type_name::<T>())).unwrap();
    }
}

mod heap;
mod read_env_value;
mod threads;
mod processes;

const TESTS: &[(&str, &[&dyn Testable])] = &[
    read_env_value::TESTS,
    heap::TESTS,
    threads::TESTS,
    processes::TESTS,
];

/// The main entry point.
///
/// # Panics
/// Right now we panic if any errors happen.
#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    for (group_name, tests) in TESTS {
        write_log(
            3,
            &format!("running test group {group_name} ({} tests)...", tests.len()),
        )
        .unwrap();
        for test in *tests {
            test.run();
        }
    }
    write_log(3, "all tests passed!").unwrap();

    exit_current_thread(0);
}

/// The panic handler.
#[panic_handler]
pub fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    let _ = write_log(1, &format!("panic! {info}"));
    exit_current_thread(1);
}
