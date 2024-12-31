//! System call wrapper functions.
use core::{arch::asm, mem::transmute};

use super::*;

/// Reads a value from the kernel about the current process environment.
/// Unlike all other system calls, because this call is infallible, the value to be read is returned from the call instead of an error.
#[must_use]
pub fn read_env_value(value_to_read: EnvironmentValue) -> usize {
    let result: usize;
    unsafe {
        asm!(
            "mov {val_to_read:x}, x0",
            "svc {call_number}",
            "mov x0, {res}",
            val_to_read = in(reg) value_to_read.into_integer(),
            res = out(reg) result,
            call_number = const CallNumber::ReadEnvValue.into_num()
        );
    }
    result
}

/// Exit the current thread, causing it to stop executing and allowing its resources to be cleaned up.
/// If this is the last thread in its process, then the process itself will exit with the same exit code.
/// This function does not return to the caller, since the thread is finished executing.
pub fn exit_current_thread(code: u32) -> ! {
    unsafe {
        asm!(
            "mov {code:x}, x0",
            "svc {call_number}",
            code = in(reg) code,
            call_number = const CallNumber::ExitCurrentThread.into_num()
        );
    }
    unreachable!()
}
