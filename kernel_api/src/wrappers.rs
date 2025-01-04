//! System call wrapper functions.
use core::{arch::asm, mem::MaybeUninit};

use super::*;

/// Reads a value from the kernel about the current process environment.
/// Unlike all other system calls, because this call is infallible, the value to be read is returned from the call instead of an error.
#[must_use]
pub fn read_env_value(value_to_read: EnvironmentValue) -> usize {
    let result: usize;
    unsafe {
        asm!(
            "mov x0, {val_to_read:x}",
            "svc {call_number}",
            "mov {res}, x0",
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
            "mov x0, {code:x}",
            "svc {call_number}",
            code = in(reg) code,
            call_number = const CallNumber::ExitCurrentThread.into_num()
        );
    }
    unreachable!()
}

/// Spawn a new thread in the current process.
/// This function also allocates new memory for the stack and inbox associated with the thread.
///
/// # Errors
/// - `OutOfMemory`: the system does not have enough memory to create the new thread.
/// - `InvalidLength`: the stack or inbox size is too small.
/// - `InvalidFlags`: an unknown or invalid flag combination was passed.
/// - `InvalidPointer`: the entry pointer was null or invalid.
pub fn spawn_thread(info: &ThreadCreateInfo) -> Result<ThreadId, ErrorCode> {
    let result: usize;
    let mut out_thread_id = MaybeUninit::uninit();
    let oti_p: *mut u32 = out_thread_id.as_mut_ptr();
    assert!(!oti_p.is_null());
    unsafe {
        asm!(
            "mov x0, {i:x}",
            "mov x1, {p:x}",
            "svc {call_number}",
            "mov {res}, x0",
            i = in(reg) info as *const ThreadCreateInfo,
            p = in(reg) oti_p,
            res = out(reg) result,
            call_number = const CallNumber::SpawnThread.into_num()
        );
    }
    if result == 0 {
        unsafe { Ok(NonZeroU32::new_unchecked(out_thread_id.assume_init())) }
    } else {
        Err(ErrorCode::from_integer(result).expect("error code"))
    }
}

/// Creates a new process. The calling process will become the parent process.
///
/// # Errors
/// - `OutOfMemory`: the system does not have enough memory to create the new process.
/// - `BadFormat`: the process image is invalid.
/// - `InvalidPointer`: a pointer was invalid or unexpectedly null.
/// - `InvalidFlags`: an unknown or invalid flag combination was passed.
pub fn spawn_process(info: &ProcessCreateInfo) -> Result<ProcessId, ErrorCode> {
    let result: usize;
    let mut out_proc_id = MaybeUninit::uninit();
    let oti_p: *mut u32 = out_proc_id.as_mut_ptr();
    assert!(!oti_p.is_null());
    unsafe {
        asm!(
            "mov x0, {i:x}",
            "mov x1, {p:x}",
            "svc {call_number}",
            "mov {res}, x0",
            i = in(reg) info as *const ProcessCreateInfo,
            p = in(reg) oti_p,
            res = out(reg) result,
            call_number = const CallNumber::SpawnProcess.into_num()
        );
    }
    if result == 0 {
        unsafe { Ok(NonZeroU32::new_unchecked(out_proc_id.assume_init())) }
    } else {
        Err(ErrorCode::from_integer(result).expect("error code"))
    }
}
