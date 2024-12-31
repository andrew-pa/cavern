//! The Cavern kernel API (i.e. system calls). See `spec/kernel.md` for the specification.
//!
//! This crate provides the definitions necessary to interact with the kernel.
//! When the `kernel` feature is not enabled, it also defines system call wrapper functions for ease of use.
#![no_std]
#![deny(missing_docs)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_possible_truncation)]

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

pub mod flags;

#[cfg(feature = "wrappers")]
mod wrappers;
#[cfg(feature = "wrappers")]
pub use wrappers::*;

#[cfg(test)]
mod tests {}
