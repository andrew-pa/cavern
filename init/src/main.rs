//! The Cavern `init` process.
//!
//! The `init` process is responsible for starting up user space.
#![no_std]
#![no_main]
#![deny(missing_docs)]

/// The main entry point.
#[unsafe(no_mangle)]
pub extern "C" fn main() {
    loop {
        unsafe { core::arch::asm!("svc #0") }
    }
}

/// The panic handler.
#[panic_handler]
pub fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    #[allow(clippy::empty_loop)]
    loop {}
}
