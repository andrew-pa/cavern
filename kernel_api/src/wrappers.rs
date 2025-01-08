//! System call wrapper functions.
use core::{arch::asm, mem::MaybeUninit, ptr};

use super::{
    CallNumber, Contiguous, EnvironmentValue, ErrorCode, NonZeroU32, ProcessCreateInfo, ProcessId,
    ThreadCreateInfo, ThreadId,
};

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
            i = in(reg) ptr::from_ref(info),
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
            i = in(reg) ptr::from_ref(info),
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

/// Kill a process by process id.
///
/// # Errors
/// - `NotFound`: the process id was not found.
pub fn kill_process(pid: ProcessId) -> Result<(), ErrorCode> {
    let result: usize;
    unsafe {
        asm!(
            "mov x0, {i:x}",
            "svc {call_number}",
            "mov {res}, x0",
            i = in(reg) pid.get(),
            res = out(reg) result,
            call_number = const CallNumber::KillProcess.into_num()
        );
    }
    if result == 0 {
        Ok(())
    } else {
        Err(ErrorCode::from_integer(result).expect("error code"))
    }
}

/// Allocates new system memory, mapping it into the current process' address space as a continuous region.
/// The contents of the memory are undefined.
///
/// # Errors
/// - `OutOfMemory`: the system does not have enough memory to make the allocation.
/// - `InvalidLength`: the size of the allocation is invalid.
/// - `InvalidFlags`: an unknown or invalid flag combination was passed.
/// - `InvalidPointer`: the destination pointer was null or invalid.
pub fn allocate_heap_pages(size: usize) -> Result<*mut u8, ErrorCode> {
    let result: usize;
    let mut out = MaybeUninit::uninit();
    unsafe {
        asm!(
            "mov x0, {s:x}",
            "mov x1, {p:x}",
            "svc {call_number}",
            "mov {res}, x0",
            s = in(reg) size,
            p = in(reg) out.as_mut_ptr(),
            res = out(reg) result,
            call_number = const CallNumber::AllocateHeapPages.into_num()
        );
    }
    if result == 0 {
        unsafe { Ok(out.assume_init()) }
    } else {
        Err(ErrorCode::from_integer(result).expect("error code"))
    }
}

/// Frees memory previously allocated by `allocate_heap_pages` from the process' address space, allowing another process to use it.
/// The base address pointer is invalid to access after calling this function.
///
/// # Errors
/// - `InvalidFlags`: an unknown or invalid flag combination was passed.
/// - `InvalidLength`: the size of the allocation is invalid.
/// - `InvalidPointer`: the base address pointer was null or invalid.
pub fn free_heap_pages(ptr: *mut u8, size: usize) -> Result<(), ErrorCode> {
    let result: usize;
    unsafe {
        asm!(
            "mov x0, {p:x}",
            "mov x1, {s:x}",
            "svc {call_number}",
            "mov {res}, x0",
            s = in(reg) size,
            p = in(reg) ptr,
            res = out(reg) result,
            call_number = const CallNumber::FreeHeapPages.into_num()
        );
    }
    if result == 0 {
        Ok(())
    } else {
        Err(ErrorCode::from_integer(result).expect("error code"))
    }
}
