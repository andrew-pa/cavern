//! The registry service allows programs to resolve resources provided by other components by name.
//! This allows client processes to discover server processes and also provides some access control.
#![no_std]
#![no_main]
#![deny(missing_docs)]
#![allow(clippy::cast_possible_truncation)]

extern crate alloc;

use alloc::string::String;
use bytemuck::Contiguous;
use kernel_api::{ErrorCode, exit_current_thread, write_log};
use snafu::{ResultExt, Snafu};

#[global_allocator]
static ALLOCATOR: user_core::heap::GlobalAllocator = user_core::heap::init_allocator();

/// Errors
#[derive(Debug, Snafu)]
pub enum Error {
    /// System call returned an error.
    #[snafu(display("System call failed: {cause}"))]
    SysCall {
        /// Message
        cause: String,
        /// Underlying error code
        source: ErrorCode,
    },
}

fn main() -> Result<(), Error> {
    write_log(3, "Hello from resource registry!").context(SysCallSnafu { cause: "write log" })?;
    Ok(())
}

/// The main entry point.
///
/// # Panics
/// Right now we panic if any errors happen.
#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    match main() {
        Ok(()) => exit_current_thread(0),
        Err(e) => {
            let s = alloc::format!("{}", snafu::Report::from_error(&e));
            let _ = write_log(1, &s);
            exit_current_thread(match e {
                Error::SysCall { source, .. } => source.into_integer() as u32 + 0x1000,
                _ => 1,
            });
        }
    }
}

/// The panic handler.
#[panic_handler]
pub fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    let _ = write_log(1, "panic!");
    if let Some(s) = info.message().as_str() {
        let _ = write_log(1, s);
    }
    exit_current_thread(1);
}
