//! System call wrapper functions.
use core::{arch::asm, mem::MaybeUninit, ptr};

use crate::{
    Message, QueueId, SharedBufferCreateInfo, SharedBufferId,
    flags::{ExitNotificationSubscriptionFlags, FreeMessageFlags, ReceiveFlags},
};

use super::{
    CallNumber, Contiguous, EnvironmentValue, ErrorCode, NonZeroU32, ProcessCreateInfo, ProcessId,
    ThreadCreateInfo, ThreadId,
};

/// Convert a return value into a `Result` for system calls that don't return values.
#[inline]
fn process_result(result: usize) -> Result<(), ErrorCode> {
    if result == 0 {
        Ok(())
    } else {
        Err(ErrorCode::from_integer(result).expect("error code"))
    }
}

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
pub fn spawn_process(info: &ProcessCreateInfo) -> Result<(ProcessId, QueueId), ErrorCode> {
    let mut result: usize;
    let mut out_proc_id = MaybeUninit::uninit();
    let mut out_qu_id = MaybeUninit::uninit();
    let oti_p: *mut u32 = out_proc_id.as_mut_ptr();
    assert!(!oti_p.is_null());
    unsafe {
        asm!(
            "mov x0, {i:x}",
            "mov x1, {p:x}",
            "mov x2, {q:x}",
            "svc {call_number}",
            "mov {res}, x0",
            i = in(reg) ptr::from_ref(info),
            p = in(reg) oti_p,
            q = in(reg) out_qu_id.as_mut_ptr(),
            res = out(reg) result,
            call_number = const CallNumber::SpawnProcess.into_num()
        );
    }
    if result == 0 {
        unsafe {
            Ok((
                NonZeroU32::new_unchecked(out_proc_id.assume_init()),
                NonZeroU32::new_unchecked(out_qu_id.assume_init()),
            ))
        }
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
    process_result(result)
}

/// Subscribes the current process to the exit notification sent when another process or thread exits.
///
/// When unsubscribing, the `receiver_tid` will only unregister the designated receiver thread if `None` is passed, not if the id of that thread is passed.
///
/// # Arguments
/// | Name       | Type                 | Notes                            |
/// |------------|----------------------|----------------------------------|
/// | `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |
/// | `pid_or_tid` |  Process/Thread ID   | The ID to subscribe to. |
/// | `receiver_tid` | Optional thread ID | The ID of the thread in this process that will receive the message. If `None`, then the designated receiver thread will get it. |
///
/// # Flags
/// The `exit_notification_subscription` call accepts the following flags:
///
/// | Name           | Description                              |
/// |----------------|------------------------------------------|
/// | `PROCESS`      | The ID parameter is a process. Mutex with `THREAD`. |
/// | `THREAD`       | The ID parameter is a thread. Mutex with `PROCESS`. |
/// | `UNSUBSCRIBE`  | Unsubscribes the current process if it was already subscribed. |
///
/// # Notification Message
/// When the exit occurs, the kernel will send a message with the sender process/thread ID [`super::KERNEL_FAKE_ID`].
/// This message will contain an [`super::ExitMessage`] struct describing the process that exited
/// and the reason for the exit.
///
/// # Errors
/// - `NotFound`: the handle was unknown or invalid.
/// - `InvalidFlags`: the flags value was invalid.
pub fn exit_notification_subscription(
    flags: ExitNotificationSubscriptionFlags,
    pid_or_tid: u32,
    receiver_qid: QueueId,
) -> Result<(), ErrorCode> {
    let mut result: usize;
    unsafe {
        asm!(
            "mov x0, {f:x}",
            "mov x1, {p:x}",
            "mov x2, {r:x}",
            "svc {call_number}",
            "mov {res}, x0",
            f = in(reg) flags.bits(),
            p = in(reg) pid_or_tid,
            r = in(reg) receiver_qid.get(),
            res = out(reg) result,
            call_number = const CallNumber::ExitNotificationSubscription.into_num()
        );
    }
    process_result(result)
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
    process_result(result)
}

/// The `send` system call allows a process to send a message to another process.
/// The kernel will inspect the message header and automatically process any associated memory operations while it generates the header on the receiver side.
/// The message body will be copied to the receiver.
///
/// # Arguments
/// | Name       | Type                 | Notes                            |
/// |------------|----------------------|----------------------------------|
/// | `dst_qid` | Queue ID           | The ID of the queue that will receive the message. |
/// | `msg`      | `*const [u8]`| Pointer to the start of memory in user space that contains the message payload. |
/// | `msg_len`  | `usize` | Length of the message payload in bytes. |
/// | `buffers`  | `*const [SharedBufferDesc]`| Pointer to array of shared buffers to send with this message. |
/// | `buffers_len`| `usize`| Length of the buffers array in elements. |
///
/// # Errors
/// - `NotFound`: the queue ID was unknown to the system.
/// - `InboxFull`: the receiving process has too many queued messages and cannot receive the message.
/// - `InvalidLength`: the length of the message is invalid.
/// - `InvalidFlags`: an unknown or invalid flag combination was passed.
/// - `InvalidPointer`: the message pointer was null or invalid.
pub fn send(
    dst_qid: QueueId,
    message: &[u8],
    buffers: &[SharedBufferCreateInfo],
) -> Result<(), ErrorCode> {
    let mut result: usize;
    unsafe {
        asm!(
            "mov x0, {qid:x}",
            "mov x1, {msg:x}",
            "mov x2, {len:x}",
            "mov x3, {bufs:x}",
            "mov x4, {bufs_len:x}",
            "svc {call_number}",
            "mov {res}, x0",
            qid = in(reg) dst_qid.get(),
            msg = in(reg) message.as_ptr(),
            len = in(reg) message.len(),
            bufs = in(reg) buffers.as_ptr(),
            bufs_len = in(reg) buffers.len(),
            res = out(reg) result,
            call_number = const CallNumber::Send.into_num()
        );
    }
    process_result(result)
}

/// The `receive` system call allows a process to receive a message from another process.
/// By default, shared buffers are automatically given handles if attached, and their details relative to the receiver will be present in the received message header.
/// The pointer returned by `receive` is valid until the message is marked for deletion.
///
/// This call will by default set the thread to a waiting state if there are no messages.
/// The thread will resume its running state when it receives a message.
/// This can be disabled with the `Nonblocking` flag, which will return `WouldBlock` as an error instead if there are no messages.
///
/// # Arguments
/// | Name       | Type                 | Notes                            |
/// |------------|----------------------|----------------------------------|
/// | `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |
/// | `queue`    | Queue ID             | The ID of the queue to receive the message from. The caller process must own this queue. |
/// | `msg`      | `*mut *mut [MessageBlock]`| Writes the pointer to the received message data here. |
/// | `len`      | `*mut u8`            | Writes the number of blocks the message contains total. |
///
/// # Flags
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
/// - `NotFound`: the queue ID was unknown to the system or not owned by this process.
pub fn receive(flags: ReceiveFlags, queue: QueueId) -> Result<Message, ErrorCode> {
    let mut result: usize;
    let mut out_len = MaybeUninit::uninit();
    let mut out_msg = MaybeUninit::uninit();
    unsafe {
        asm!(
            "mov x0, {f:x}",
            "mov x1, {q:x}",
            "mov x2, {m:x}",
            "mov x3, {l:x}",
            "svc {call_number}",
            "mov {res}, x0",
            f = in(reg) flags.bits(),
            q = in(reg) queue.get(),
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

/// Free a message, making its space in the inbox available for new messages.
///
/// # Arguments
/// | Name       | Type                 | Notes                            |
/// |------------|----------------------|----------------------------------|
/// | `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |
/// | `msg`      | `*mut [MessageBlock]`| the pointer to the received message data. |
/// | `len`      | `usize`| Length in bytes of the entire message, as returned by `receive()`. |
///
/// # Flags
/// The `free_message` call accepts the following flags:
///
/// | Name           | Description                              |
/// |----------------|------------------------------------------|
/// | `FreeBuffers` | If set, frees all shared buffers attached to this message that are not already freed. |
///
/// # Errors
/// - `InvalidFlags`: an unknown or invalid flag combination was passed.
/// - `InvalidPointer`: the message pointer was null or invalid.
#[allow(clippy::needless_pass_by_value)] // pass by value is important here for safety
pub fn free_message(flags: FreeMessageFlags, message: Message) -> Result<(), ErrorCode> {
    let mut result: usize;
    unsafe {
        asm!(
            "mov x0, {f:x}",
            "mov x1, {p:x}",
            "mov x2, {l:x}",
            "svc {call_number}",
            "mov {res}, x0",
            f = in(reg) flags.bits(),
            p = in(reg) message.ptr,
            l = in(reg) message.len,
            res = out(reg) result,
            call_number = const CallNumber::FreeMessage.into_num()
        );
    }
    process_result(result)
}

/// Copy bytes from the caller process into a shared buffer that has been sent to it.
/// Only valid if the sender has allowed writes to the buffer.
///
/// # Arguments
/// | Name       | Type                 | Notes                            |
/// |------------|----------------------|----------------------------------|
/// | `buffer_handle` | buffer handle   | Handle to the shared buffer to copy into. |
/// | `dst_offset` | u64                | Offset into the shared buffer to start writing bytes to. |
/// | `src_address` | `*const u8`       | Source address to copy from in the calling process. |
/// | `length` | u64                    | Length of the copy in bytes. |
///
/// # Errors
/// - `NotFound`: an unknown buffer handle was passed.
/// - `InvalidPointer`: the message pointer or length pointer was null or invalid.
/// - `InvalidLength`: the requested operation would extend past the end of the buffer.
pub fn transfer_to_shared_buffer(
    buffer: SharedBufferId,
    dst_offset: usize,
    src: &[u8],
) -> Result<(), ErrorCode> {
    let mut result: usize;
    unsafe {
        asm!(
            "mov x0, {b:x}",
            "mov x1, {d:x}",
            "mov x2, {s:x}",
            "mov x3, {l:x}",
            "svc {call_number}",
            "mov {res}, x0",
            b = in(reg) buffer.get(),
            d = in(reg) dst_offset,
            s = in(reg) src.as_ptr(),
            l = in(reg) src.len(),
            res = out(reg) result,
            call_number = const CallNumber::TransferToSharedBuffer.into_num()
        );
    }
    process_result(result)
}

/// Copy bytes from a shared buffer to the caller process.
/// Only valid if the sender has allowed reads from the buffer.
///
/// # Arguments
/// | Name       | Type                 | Notes                            |
/// |------------|----------------------|----------------------------------|
/// | `buffer_handle` | buffer handle   | Handle to the shared buffer to copy from. |
/// | `src_offset` | u64                | Offset into the shared buffer to start reading bytes from. |
/// | `dst_address` | `*const u8`       | Destination address to copy to in the calling process. |
/// | `length` | u64                    | Length of the copy in bytes. |
///
/// # Errors
/// - `InvalidFlags`: an unknown or invalid flag combination was passed.
/// - `NotFound`: an unknown buffer handle was passed.
/// - `InvalidPointer`: the message pointer or length pointer was null or invalid.
/// - `InvalidLength`: the requested operation would extend past the end of the buffer.
pub fn transfer_from_shared_buffer(
    buffer: SharedBufferId,
    src_offset: usize,
    dst: &mut [u8],
) -> Result<(), ErrorCode> {
    let mut result: usize;
    unsafe {
        asm!(
            "mov x0, {b:x}",
            "mov x1, {s:x}",
            "mov x2, {d:x}",
            "mov x3, {l:x}",
            "svc {call_number}",
            "mov {res}, x0",
            b = in(reg) buffer.get(),
            s = in(reg) src_offset,
            d = in(reg) dst.as_ptr(),
            l = in(reg) dst.len(),
            res = out(reg) result,
            call_number = const CallNumber::TransferFromSharedBuffer.into_num()
        );
    }
    process_result(result)
}

/// Release a group of shared buffer handle, freeing up its resources.
/// This does not free the memory in the owner process.
/// If one of the handles does not exist, the rest will still be freed but `NotFound` will be returned.
///
///#### Arguments
/// | Name       | Type                 | Notes                            |
/// |------------|----------------------|----------------------------------|
/// | `buffer_handles` | buffer handle array | Handles to free.            |
/// | `length`   | u64                  | Number of handles in the array.  |
///
/// # Errors
/// - `NotFound`: one or more of the handles was unknown
/// - `InvalidPointer`: the array pointer was null or invalid.
/// - `InvalidLength`: the length value was invalid.
pub fn free_shared_buffers(buffers: &[SharedBufferId]) -> Result<(), ErrorCode> {
    let mut result: usize;
    unsafe {
        asm!(
            "mov x0, {bufs:x}",
            "mov x1, {bufs_len:x}",
            "svc {call_number}",
            "mov {res}, x0",
            bufs = in(reg) buffers.as_ptr(),
            bufs_len = in(reg) buffers.len(),
            res = out(reg) result,
            call_number = const CallNumber::FreeSharedBuffers.into_num()
        );
    }
    process_result(result)
}

/// ### `create_message_queue`
/// Creates a new message queue owned by the calling process.
///
/// #### Arguments
/// | Name       | Type                 | Notes                            |
/// |------------|----------------------|----------------------------------|
/// | `qid`      | `*mut Queue ID`| The destination for the ID of the newly created queue. |
///
/// #### Errors
/// - `InvalidPointer`: the destination ID pointer was invalid.
/// - `OutOfHandles`: the system has run out of handles to use.
pub fn create_message_queue() -> Result<QueueId, ErrorCode> {
    let mut result: usize;
    let mut out = MaybeUninit::uninit();
    unsafe {
        asm!(
            "mov x0, {p:x}",
            "svc {call_number}",
            "mov {res}, x0",
            p = in(reg) out.as_mut_ptr(),
            res = out(reg) result,
            call_number = const CallNumber::CreateMessageQueue.into_num()
        );
    }
    if result == 0 {
        unsafe { Ok(out.assume_init()) }
    } else {
        Err(ErrorCode::from_integer(result).expect("error code"))
    }
}

/// ### `free_message_queue`
/// Frees a message queue owned by the calling process.
/// Any pending messages in the queue are freed from the process' inbox.
///
/// #### Arguments
/// | Name       | Type                 | Notes                            |
/// |------------|----------------------|----------------------------------|
/// | `qid`      | `Queue ID`| The ID of the queue to free. |
pub fn free_message_queue(queue: QueueId) -> Result<(), ErrorCode> {
    let mut result: usize;
    unsafe {
        asm!(
            "mov x0, {q:x}",
            "svc {call_number}",
            "mov {res}, x0",
            q = in(reg) queue.get(),
            res = out(reg) result,
            call_number = const CallNumber::FreeMessageQueue.into_num()
        );
    }
    process_result(result)
}

/// Writes a message to the kernel log with log level `level` (a `log::Level`).
/// This is for early boot user space components, before user space logging is set up.
///
/// # Errors
/// - `InvalidFlags` if the log level is invalid (not in [1,5]).
/// - `InvalidPointer` if the message slice is not valid.
pub fn write_log(level: usize, msg: &str) -> Result<(), ErrorCode> {
    let mut result: usize;
    unsafe {
        asm!(
            "mov x0, {l:x}",
            "mov x1, {m:x}",
            "mov x2, {ml:x}",
            "svc {call_number}",
            "mov {res}, x0",
            l = in(reg) level,
            m = in(reg) msg.as_ptr(),
            ml = in(reg) msg.len(),
            res = out(reg) result,
            call_number = const CallNumber::WriteLogMessage.into_num()
        );
    }
    process_result(result)
}
