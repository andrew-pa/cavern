//! The Cavern kernel API (i.e. system calls). See `spec/kernel.md` for the specification.
//!
//! This crate provides the definitions necessary to interact with the kernel.
//! When the `kernel` feature is not enabled, it also defines system call wrapper functions for ease of use.
#![no_std]
#![deny(missing_docs)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_possible_truncation)]

use core::num::NonZeroU32;

use bytemuck::Contiguous;

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
}

/// System call numbers, one per call.
/// See the specification for more details.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Contiguous)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum CallNumber {
    Send = 0x100,
    Recieve,
    TransferToSharedBuffer,
    TransferFromSharedBuffer,
    ReadEnvValue,
    SpawnProcess,
    SpawnThread,
    ExitCurrentThread,
    KillProcess,
    SetDesignatedReciever,
    AllocateHeapPages,
    FreeHeapPages,
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
pub enum ExitReason {
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
    /// The size of the new thread's inbox in pages.
    pub inbox_size: usize,
    /// The user paramter that will be passed to the entry point function.
    pub user_data: usize,
}

/// The unique ID of a process.
pub type ProcessId = NonZeroU32;

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
}

pub mod flags;

#[cfg(feature = "wrappers")]
mod wrappers;
#[cfg(feature = "wrappers")]
pub use wrappers::*;

#[cfg(test)]
mod tests {}
