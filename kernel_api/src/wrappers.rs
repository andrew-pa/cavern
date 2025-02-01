//! System call wrapper functions.
use core::{arch::asm, mem::MaybeUninit, ptr};

use crate::{Message, SharedBufferCreateInfo, flags::ReceiveFlags};

use super::{
    CallNumber, Contiguous, EnvironmentValue, ErrorCode, NonZeroU32, ProcessCreateInfo, ProcessId,
    ThreadCreateInfo, ThreadId,
};

/// Reads a value from the kernel about the current process environment.
/// Unlike all other system calls, because this call is infallible, the value to be read is returned from the call instead of an error.
#[must_use]
pub fn read_env_value(value_to_read: EnvironmentValue) -> usize {
    let mut result: usize;
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
    let mut result: usize;
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
    let mut result: usize;
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
    let mut result: usize;
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
    let mut result: usize;
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
    let mut result: usize;
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

/// The `send` system call allows a process to send a message to another process.
/// The kernel will inspect the message header and automatically process any associated memory operations while it generates the header on the receiver side.
/// The message body will be copied to the receiver.
///
/// # Arguments
/// | Name       | Type                 | Notes                            |
/// |------------|----------------------|----------------------------------|
/// | `dst_pid` | Process ID           | The ID of the process that will receive the message. |
/// | `dst_tid` | Thread ID or zero    | Optional ID of the thread that will receive the message, or zero to send to the receiver's designated thread. |
/// | `msg`      | `*const [u8]`| Pointer to the start of memory in user space that contains the message payload. |
/// | `msg_len`  | `usize` | Length of the message payload in bytes. |
/// | `buffers`  | `*const [SharedBufferDesc]`| Pointer to array of shared buffers to send with this message. |
/// | `buffers_len`| `usize`| Length of the buffers array in elements. |
///
/// # Errors
/// - `NotFound`: the process/thread ID was unknown to the system.
/// - `InboxFull`: the receiving process has too many queued messages and cannot receive the message.
/// - `InvalidLength`: the length of the message is invalid.
/// - `InvalidFlags`: an unknown or invalid flag combination was passed.
/// - `InvalidPointer`: the message pointer was null or invalid.
pub fn send(
    dst_process_id: ProcessId,
    dst_thread_id: Option<ThreadId>,
    message: &[u8],
    buffers: &[SharedBufferCreateInfo],
) -> Result<(), ErrorCode> {
    let mut result: usize;
    unsafe {
        asm!(
            "mov x0, {pid:x}",
            "mov x1, {tid:x}",
            "mov x2, {msg:x}",
            "mov x3, {len:x}",
            "mov x4, {bufs:x}",
            "mov x5, {bufs_len:x}",
            "svc {call_number}",
            "mov {res}, x0",
            pid = in(reg) dst_process_id.get(),
            tid = in(reg) dst_thread_id.map_or(0, ThreadId::get),
            msg = in(reg) message.as_ptr(),
            len = in(reg) message.len(),
            bufs = in(reg) buffers.as_ptr(),
            bufs_len = in(reg) buffers.len(),
            res = out(reg) result,
            call_number = const CallNumber::Send.into_num()
        );
    }
    if result == 0 {
        Ok(())
    } else {
        Err(ErrorCode::from_integer(result).expect("error code"))
    }
}

/// The `receive` system call allows a process to receive a message from another process.
/// By default, shared buffers are automatically given handles if attached, and their details relative to the receiver will be present in the received message header.
/// The pointer returned by `receive` is valid until the message is marked for deletion.
///
/// This call will by default set the thread to a waiting state if there are no messages.
/// The thread will resume its running state when it receives a message.
/// This can be disabled with the `Nonblocking` flag, which will return `WouldBlock` as an error instead if there are no messages.
///
/// #### Arguments
/// | Name       | Type                 | Notes                            |
/// |------------|----------------------|----------------------------------|
/// | `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |
/// | `msg`      | `*mut *mut [MessageBlock]`| Writes the pointer to the received message data here. |
/// | `len`      | `*mut u8`            | Writes the number of blocks the message contains total. |
///
/// #### Flags
/// The `receive` call accepts the following flags:
///
/// | Name           | Description                              |
/// |----------------|------------------------------------------|
/// | `Nonblocking`  | Causes the kernel to return the `WouldBlock` error if there are no messages instead of pausing the thread. |
/// | `IgnoreShared` | Causes the kernel to ignore any shared buffers contained in the received message. |
///
/// # Errors
/// - `WouldBlock`: returned in non-blocking mode if there are no messages to receive.
/// - `InvalidFlags`: an unknown or invalid flag combination was passed.
/// - `InvalidPointer`: the message pointer or length pointer was null or invalid.
pub fn receive<'a>(flags: ReceiveFlags) -> Result<&'a Message, ErrorCode> {
    let mut result: usize;
    let mut out_len = MaybeUninit::uninit();
    let mut out_msg = MaybeUninit::uninit();
    unsafe {
        asm!(
            "mov x1, {f:x}",
            "mov x1, {m:x}",
            "mov x2, {l:x}",
            "svc {call_number}",
            "mov {res}, x0",
            f = in(reg) flags.bits(),
            m = in(reg) out_msg.as_mut_ptr(),
            l = in(reg) out_len.as_mut_ptr(),
            res = out(reg) result,
            call_number = const CallNumber::Receive.into_num()
        );
    }
    if result == 0 {
        unsafe { Ok(Message::new(out_msg.assume_init(), out_len.assume_init())) }
    } else {
        Err(ErrorCode::from_integer(result).expect("error code"))
    }
}
