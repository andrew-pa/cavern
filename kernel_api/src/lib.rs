//! The Cavern kernel API (i.e. system calls). See `spec/kernel.md` for the specification.
//!
//! This crate provides the definitions necessary to interact with the kernel.
//! When the `kernel` feature is not enabled, it also defines system call wrapper functions for ease of use.
#![no_std]
#![deny(missing_docs)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_possible_truncation)]
#![feature(pointer_is_aligned_to)]

use core::num::NonZeroU32;

use bytemuck::{Contiguous, Pod, Zeroable};

/// Errors that can arise during a system call.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Contiguous)]
#[repr(usize)]
pub enum ErrorCode {
    /// The specified process, thread, or handler ID was unknown or not found in the system.
    NotFound = 1,

    /// The provided data was incorrectly formatted (e.g., message header, process image, interrupt data).
    BadFormat,

    /// The receiving process's message queue is full, and it cannot accept additional messages.
    InboxFull,

    /// The specified length was invalid, out of bounds, or not in the acceptable range.
    InvalidLength,

    /// An unknown, unsupported, or invalid combination of flags was passed.
    InvalidFlags,

    /// A pointer provided was null, invalid, or otherwise could not be used as expected.
    InvalidPointer,

    /// The system does not have enough available memory to complete the requested operation.
    OutOfMemory,

    /// The specified address or memory region was outside the allowed range or otherwise invalid.
    OutOfBounds,

    /// The system has run out of free handles for the requested resource.
    OutOfHandles,

    /// The operation would block the calling thread, but non-blocking mode was specified.
    WouldBlock,

    /// The requested resource or memory region is already in use by another process or driver.
    InUse,

    /// The buffer was not shared with the permissions required for the operation.
    InsufficentPermissions,
}

/// System call numbers, one per call.
/// See the specification for more details.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Contiguous)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum CallNumber {
    Send = 0x100,
    Receive,
    TransferToSharedBuffer,
    TransferFromSharedBuffer,
    ReadEnvValue,
    SpawnProcess,
    SpawnThread,
    ExitCurrentThread,
    KillProcess,
    SetDesignatedReceiver,
    AllocateHeapPages,
    FreeHeapPages,
    FreeMessage,
    FreeSharedBuffers,
    ExitNotificationSubscription,
}

impl CallNumber {
    /// Convert a variant into its numerical representation, but marked `const`.
    const fn into_num(self) -> u16 {
        // Safe because we are `Contiguous`.
        unsafe { core::mem::transmute(self) }
    }
}

/// Values that can be read to determine the environment of a process.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Contiguous)]
#[repr(usize)]
pub enum EnvironmentValue {
    /// The process ID of the calling process.
    CurrentProcessId = 1,
    /// The thread ID of the calling process.
    CurrentThreadId,
    /// The thread ID of the calling process' designated receiver thread.
    DesignatedReceiverThreadId,
    /// The process ID of the supervisor process for the calling process.
    CurrentSupervisorId,
    /// The number of bytes per page of memory.
    PageSizeInBytes,
}

/// The reason that a thread/process exited.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(C)]
pub enum ExitReasonOld {
    /// The thread requested the exit with the given code.
    /// The code `0` implies the thread exited in a non-error/successful state, otherwise an error is assumed.
    User(u32),
    /// The thread accessed unmapped or protected virtual memory.
    PageFault,
    /// The thread made a system call with an invalid system call number.
    InvalidSysCall,
    /// Another thread/process caused this thread to exit prematurely.
    Killed,
}

/// The unique ID of a thread.
pub type ThreadId = NonZeroU32;

/// Parameters for creating a new thread.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ThreadCreateInfo {
    /// The entry point for the new thread.
    pub entry: fn(usize) -> !,
    /// The size of the new thread's stack in pages.
    pub stack_size: usize,
    /// The user paramter that will be passed to the entry point function.
    pub user_data: usize,
}

/// The unique ID of a process.
pub type ProcessId = NonZeroU32;

/// The process id given as the sender for notifications originating from the kernel that have no
/// other sender.
pub const KERNEL_FAKE_PID: ProcessId = ProcessId::new(0xffff_ffff).unwrap();

/// Level of privilege granted to a process.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Contiguous, Default)]
#[repr(u8)]
pub enum PrivilegeLevel {
    /// Unprivileged processes cannot send messages to other processes outside their supervisor's children.
    /// This is the lowest level of privilege.
    #[default]
    Unprivileged,
    /// Privileged processes can send messages to other processes outside their supervisor's children, but not outside their supervisor's supervisor's children.
    Privileged,
    /// A driver process can send messages to any process in the system.
    /// Driver processes can also call the `driver_*` system calls.
    /// This is the highest level of privilege.
    Driver,
}

/// The type of a image section.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Contiguous)]
#[repr(u8)]
pub enum ImageSectionKind {
    /// Immutable data.
    ReadOnly,
    /// Mutable data.
    ReadWrite,
    /// Executable program code.
    Executable,
}

/// A section of memory in a process image.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ImageSection {
    /// The base address in the process' address space. This must be page aligned.
    pub base_address: usize,
    /// Offset from the base address where the `data` will be copied to. Any bytes between the
    /// start and the offset will be zeroed.
    pub data_offset: usize,
    /// The total size of the section in bytes (including the `data_offset` bytes).
    /// Any bytes past the size of `data` will be zeroed.
    pub total_size: usize,
    /// Number of bytes that `data` points to.
    pub data_size: usize,
    /// The data that will be copied into the section.
    pub data: *const u8,
    /// The type of section this is.
    pub kind: ImageSectionKind,
}

/// Parameters for creating a new process.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ProcessCreateInfo {
    /// The main entry point in the process image.
    pub entry_point: usize,
    /// The number of process image sections.
    pub num_sections: usize,
    /// The process image sections that will be loaded into the new process.
    pub sections: *const ImageSection,
    /// The new process' supervisor, or None to inherit.
    pub supervisor: Option<ProcessId>,
    /// The new process' privilege level (must be less than or equal to the current privilege level).
    pub privilege_level: PrivilegeLevel,
    /// Whether to notify this process via a message when the spawned process exits.
    pub notify_on_exit: bool,
    /// The size of this process' message inbox, in message blocks.
    pub inbox_size: usize,
}

/// The size of a message block in bytes.
pub const MESSAGE_BLOCK_SIZE: usize = 64;

/// The header containing information about a received message.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(8))]
pub struct MessageHeader {
    /// The process id of the process that send this message.
    pub sender_pid: ProcessId,
    /// The thread id of the thread that send this message.
    pub sender_tid: ThreadId,
    /// The number of shared buffers sent in this message.
    pub num_buffers: usize,
}

/// A received message from another process.
#[repr(C, align(8))]
pub struct Message([u8]);

impl Message {
    /// Create a new message from a raw slice in the inbox.
    /// The `len` must be the length in bytes.
    ///
    /// # Safety
    /// The caller ensures that this slice is valid: that it actually contains a message with a valid header.
    /// This means at a minimum that `len` must be greater than `size_of::<MessageHeader>()` and `ptr` must be
    /// aligned to an 8-byte boundary.
    unsafe fn new<'a>(ptr: *mut u8, len: usize) -> &'a Message {
        unsafe {
            let slice = core::slice::from_raw_parts(ptr, len);
            Self::from_slice(slice)
        }
    }

    /// Create a new message from a slice in the inbox.
    ///
    /// # Safety
    /// The caller ensures that this slice is valid: that it actually contains a message with a valid header.
    /// This means at a minimum that `len` must be greater than `size_of::<MessageHeader>()` and `ptr` must be aligned to an 8-byte boundary.
    pub unsafe fn from_slice(slice: &[u8]) -> &Message {
        debug_assert!(
            slice.len() >= core::mem::size_of::<MessageHeader>(),
            "message must be at least large enough for a message header"
        );
        let ptr = slice.as_ptr();
        debug_assert!(ptr.is_aligned_to(8), "messages must be 8-byte aligned");
        unsafe {
            #[allow(clippy::cast_ptr_alignment)]
            &*(core::ptr::from_ref(slice) as *const Message)
        }
    }

    /// The message header written by the kernel.
    #[must_use]
    pub fn header(&self) -> &MessageHeader {
        unsafe {
            // SAFETY: a message is guarenteed (by the kernel) to start with a header.
            #[allow(clippy::cast_ptr_alignment)]
            self.0
                .as_ptr()
                .cast::<MessageHeader>()
                .as_ref()
                .unwrap_unchecked()
        }
    }

    /// The message payload from the sender.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let msg_hdr_size = core::mem::size_of::<MessageHeader>()
            + self.header().num_buffers * core::mem::size_of::<SharedBufferInfo>();
        unsafe {
            // SAFETY: a message is guarenteed (by the kernel) to have the payload after the header.
            let ptr = self.0.as_ptr().cast::<u8>().add(msg_hdr_size);
            core::slice::from_raw_parts(ptr, self.0.len() - msg_hdr_size)
        }
    }

    /// The attached shared buffers for this message.
    #[must_use]
    pub fn buffers(&self) -> &[SharedBufferInfo] {
        let msg_hdr_size = core::mem::size_of::<MessageHeader>();
        unsafe {
            // SAFETY: a message is guarenteed (by the kernel) to have the payload after the header.
            #[allow(clippy::cast_ptr_alignment)]
            let ptr = self
                .0
                .as_ptr()
                .byte_add(msg_hdr_size)
                .cast::<SharedBufferInfo>();
            core::slice::from_raw_parts(ptr, self.header().num_buffers)
        }
    }
}

/// The unique ID of a shared buffer local to the receiving process.
pub type SharedBufferId = NonZeroU32;

/// Description of a shared buffer on the sending side.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct SharedBufferCreateInfo {
    /// Flags for this buffer.
    pub flags: flags::SharedBufferFlags,
    /// Base address of the buffer.
    pub base_address: *mut u8,
    /// Length in bytes of this buffer.
    pub length: usize,
}

/// Description of a shared buffer on the receiving side.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct SharedBufferInfo {
    /// Flags for this buffer.
    pub flags: flags::SharedBufferFlags,
    /// Id of the buffer.
    pub buffer: SharedBufferId,
    /// Length in bytes of this buffer.
    pub length: usize,
}

/// The tag representing the exit reason. This is a C‐friendly C-like enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable, Contiguous)]
#[repr(u32)]
pub enum ExitReasonTag {
    /// The thread requested exit with the given exit code.
    User = 0,
    /// The thread accessed unmapped or protected memory.
    PageFault = 1,
    /// The thread made an invalid system call.
    InvalidSysCall = 2,
    /// The thread was killed by another thread/process.
    Killed = 3,
}

/// The C‐friendly representation of the exit reason.
/// If the reason is `User`, then `user_code` is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable)]
#[repr(C)]
pub struct ExitReason {
    /// Discriminant value.
    pub tag: ExitReasonTag,
    /// Exit code provided by the user. Only valid if tag == `ExitReasonTag::User`.
    pub user_code: u32,
}
unsafe impl Pod for ExitReason {}

impl ExitReason {
    /// Create a user exit reason with the exit code from the user.
    #[must_use]
    pub fn user(code: u32) -> Self {
        Self {
            tag: ExitReasonTag::User,
            user_code: code,
        }
    }

    /// Exit occured due to page fault.
    #[must_use]
    pub fn page_fault() -> Self {
        Self {
            tag: ExitReasonTag::PageFault,
            user_code: 0,
        }
    }

    /// Exit occured due to invalid system call.
    #[must_use]
    pub fn invalid_syscall() -> Self {
        Self {
            tag: ExitReasonTag::InvalidSysCall,
            user_code: 0,
        }
    }

    /// Exit occured because another process/thread requested it.
    #[must_use]
    pub fn killed() -> Self {
        Self {
            tag: ExitReasonTag::Killed,
            user_code: 0,
        }
    }
}

/// The tag to indicate whether this exit message is for a thread or a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable, Contiguous)]
#[repr(u32)]
pub enum ExitSource {
    /// A thread in the current process exited.
    Thread = 0,
    /// A child process exited.
    Process = 1,
}

/// The complete exit message. This is plain old data and can be safely cast to a `[u8]` buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable)]
pub struct ExitMessage {
    /// Indicates if the exit was for a thread or a process.
    pub source: ExitSource,
    /// If the exit is for a process, this is the process ID; otherwise, it is ignored.
    pub pid: u32,
    /// The reason for the exit.
    pub reason: ExitReason,
}
unsafe impl Pod for ExitMessage {}

impl ExitMessage {
    /// Create a message for a thread exit.
    #[must_use]
    pub fn thread(reason: ExitReason) -> Self {
        Self {
            source: ExitSource::Thread,
            pid: 0,
            reason,
        }
    }

    /// Create a message for a process exit.
    #[must_use]
    pub fn process(pid: u32, reason: ExitReason) -> Self {
        Self {
            source: ExitSource::Process,
            pid,
            reason,
        }
    }
}

pub mod flags;

#[cfg(feature = "wrappers")]
mod wrappers;
#[cfg(feature = "wrappers")]
pub use wrappers::*;

#[cfg(test)]
mod tests {}
