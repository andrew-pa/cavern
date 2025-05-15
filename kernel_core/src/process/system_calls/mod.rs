//! System calls from user space.
#![allow(clippy::needless_pass_by_value)]

use alloc::{string::String, sync::Arc};
use bytemuck::Contiguous;
use kernel_api::{
    flags::{ExitNotificationSubscriptionFlags, FreeMessageFlags},
    CallNumber, ErrorCode, ExitReason, Message, ProcessId, QueueId, ThreadId,
};
use log::{debug, error, warn};
use snafu::{ensure, OptionExt, ResultExt, Snafu};

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        PageAllocator, VirtualAddress, VirtualPointer,
    },
    process::{kill_thread_entirely, MessageQueue},
};

use super::{
    queue::QueueManager,
    thread::{Registers, ThreadManager},
    ManagerError, Process, ProcessManager, SharedBufferId, Thread, TransferError,
};

/// Errors that can arise during a system call.
#[derive(Debug, Snafu)]
pub enum Error {
    /// The specified length was invalid, out of bounds, or not in the acceptable range.
    #[snafu(display("Invalid length {reason}: {length}"))]
    InvalidLength {
        /// The value that was invalid or other information about what the source of the error was.
        reason: String,
        /// The invalid length value.
        length: usize,
    },
    /// An unknown, unsupported, or invalid combination of flags was passed.
    #[snafu(display("Invalid flags {reason}: 0b{bits:b}"))]
    InvalidFlags {
        /// The value that was invalid or other information about what the source of the error was.
        reason: String,
        /// The invalid flag bits (may contain valid bits as well).
        bits: usize,
    },
    /// A pointer provided was null, invalid, or otherwise could not be used as expected.
    #[snafu(display("Invalid pointer {reason}: 0x{ptr:x}"))]
    InvalidPointer {
        /// The value that was invalid or other information about what the source of the error was.
        reason: String,
        /// The invalid pointer value.
        ptr: usize,
    },
    /// A pointer provided was to an address that was not mapped correctly.
    #[snafu(display("Invalid address for {cause}"))]
    InvalidAddress {
        /// The information about what the source of the error was.
        source: crate::memory::page_table::Error,
        /// The specific value that was invalid.
        cause: String,
    },
    /// A handle provided was invalid, or otherwise could not be used as expected.
    #[snafu(display("Invalid handle {reason}: 0x{handle:x}"))]
    InvalidHandle {
        /// The value that was invalid or other information about what the source of the error was.
        reason: String,
        /// The invalid handle value.
        handle: u32,
    },
    /// The specified process, thread, or handler ID was unknown or not found in the system.
    #[snafu(display("Id {id} not found: {reason}"))]
    NotFound {
        /// The value that was missing or other information about what the source of the error was.
        reason: String,
        /// The missing id value.
        id: usize,
    },
    /// Error occurred in a manager mechanism.
    Manager {
        /// Underlying error.
        source: ManagerError,
    },
    /// Receiving a message would otherwise block the thread.
    WouldBlock,
    /// Error occured doing a shared buffer transfer.
    Transfer {
        /// Underlying error.
        source: TransferError,
    },
    /// The operation was not permitted due to insufficent access rights.
    #[snafu(display("Operation not permitted: {reason}"))]
    NotPermitted {
        /// The reason/operation attempted.
        reason: String,
    },
}

impl Error {
    /// Convert the `Error` to a error code that can be returned to user space.
    #[must_use]
    pub fn to_code(self) -> ErrorCode {
        match self {
            Error::InvalidLength { .. } => ErrorCode::InvalidLength,
            Error::InvalidFlags { .. } => ErrorCode::InvalidFlags,
            Error::InvalidPointer { .. } | Error::InvalidAddress { .. } => {
                ErrorCode::InvalidPointer
            }
            Error::InvalidHandle { .. } | Error::NotFound { .. } => ErrorCode::NotFound,
            Error::WouldBlock => ErrorCode::WouldBlock,
            Error::Manager { source } => match source {
                ManagerError::Memory { source, .. } => match source {
                    crate::memory::Error::OutOfMemory => ErrorCode::OutOfMemory,
                    crate::memory::Error::InvalidSize => ErrorCode::InvalidLength,
                    crate::memory::Error::UnknownPtr => ErrorCode::InvalidPointer,
                },
                ManagerError::PageTables { source } => match source {
                    crate::memory::page_table::Error::InvalidCount => ErrorCode::InvalidLength,
                    _ => ErrorCode::InvalidPointer,
                },
                ManagerError::Missing { cause } => {
                    error!("Missing value in process manager: {cause}");
                    ErrorCode::NotFound
                }
                ManagerError::OutOfHandles => ErrorCode::OutOfHandles,
                ManagerError::InboxFull => ErrorCode::InboxFull,
            },
            Error::Transfer { source } => match source {
                TransferError::OutOfBounds => ErrorCode::OutOfBounds,
                TransferError::InsufficentPermissions => ErrorCode::NotAllowed,
                TransferError::PageTables { .. } => ErrorCode::InvalidPointer,
            },
            Error::NotPermitted { .. } => ErrorCode::NotAllowed,
        }
    }
}

/// Effects that can result from a system call.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SysCallEffect {
    /// The system call returns normally with value `usize`.
    Return(usize),
    /// The system call does not return to the caller, but instead another thread is scheduled.
    ScheduleNextThread,
}

/// System call handler policy.
pub struct SystemCalls<
    'pa,
    'm,
    PA: PageAllocator,
    PM: ProcessManager,
    TM: ThreadManager,
    QM: QueueManager,
> {
    page_allocator: &'pa PA,
    process_manager: &'m PM,
    thread_manager: &'m TM,
    queue_manager: &'m QM,
}

// system call handler impl modules
mod allocate_heap_pages;
mod create_msg_queue;
mod exit_current_thread;
mod exit_notification_subscription;
mod free_heap_pages;
mod free_message;
mod free_msg_queue;
mod free_shared_buffers;
mod kill_process;
mod read_env_value;
mod receive;
mod send;
mod spawn_process;
mod spawn_thread;
mod transfer_from_shared_buffer;
mod transfer_to_shared_buffer;

impl<'pa, 'm, PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'pa, 'm, PA, PM, TM, QM>
{
    /// Create a new system call handler policy.
    pub fn new(
        page_allocator: &'pa PA,
        process_manager: &'m PM,
        thread_manager: &'m TM,
        queue_manager: &'m QM,
    ) -> Self {
        Self {
            page_allocator,
            process_manager,
            thread_manager,
            queue_manager,
        }
    }

    /// Execute a system call on behalf of a process.
    ///
    /// Returns a [`SysCallEffect`] if there is no error to return to user-space.
    /// - [`SysCallEffect::Return`] to return a value (zero being success) to user-space.
    /// - [`SysCallEffect::ScheduleNextThread`] to cause a different thread to be scheduled.
    ///
    ///  This may mean that the current thread was killed by this system call, either intentionally or
    ///  due to a fault (for example, because an invalid system call number was provided).
    ///
    /// # Errors
    /// Returns an error that should be reported to user-space if the system call is unsuccessful.
    pub fn dispatch_system_call<AUST: ActiveUserSpaceTables>(
        &self,
        syscall_number: u16,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: &AUST,
    ) -> Result<SysCallEffect, Error> {
        let Some(syscall_number) = CallNumber::from_integer(syscall_number) else {
            warn!(
                "invalid system call number {} provided by thread #{}",
                syscall_number, current_thread.id
            );
            kill_thread_entirely(
                self.process_manager,
                self.thread_manager,
                self.queue_manager,
                current_thread,
                ExitReason::invalid_syscall(),
            );
            return Ok(SysCallEffect::ScheduleNextThread);
        };
        let user_space_memory = user_space_memory.into();
        match syscall_number {
            CallNumber::ReadEnvValue => Ok(SysCallEffect::Return(
                self.syscall_read_env_value(current_thread, registers),
            )),
            CallNumber::SpawnThread => {
                self.syscall_spawn_thread(
                    current_thread.parent.clone().unwrap(),
                    registers,
                    user_space_memory,
                )?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::SpawnProcess => {
                self.syscall_spawn_process(
                    current_thread.parent.clone().unwrap(),
                    registers,
                    user_space_memory,
                )?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::KillProcess => {
                self.syscall_kill_process(current_thread.parent.as_ref().unwrap(), registers)?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::AllocateHeapPages => {
                self.syscall_allocate_heap_pages(
                    current_thread.parent.as_ref().unwrap(),
                    registers,
                    user_space_memory,
                )?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::FreeHeapPages => {
                self.syscall_free_heap_pages(current_thread.parent.as_ref().unwrap(), registers)?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::ExitCurrentThread => {
                self.syscall_exit_current_thread(current_thread, registers);
                Ok(SysCallEffect::ScheduleNextThread)
            }
            CallNumber::Send => {
                self.syscall_send(current_thread, registers, user_space_memory)?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::Receive => {
                self.syscall_receive(current_thread, registers, user_space_memory)
            }
            CallNumber::TransferToSharedBuffer => {
                self.syscall_transfer_to(current_thread, registers, user_space_memory)?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::TransferFromSharedBuffer => {
                self.syscall_transfer_from(current_thread, registers, user_space_memory)?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::FreeMessage => {
                self.syscall_free_message(current_thread, registers, user_space_memory)?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::FreeSharedBuffers => {
                self.syscall_free_shared_buffers(current_thread, registers, user_space_memory)?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::ExitNotificationSubscription => {
                self.syscall_exit_notification_subscription(current_thread, registers)?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::WriteLogMessage => {
                self.syscall_write_log(current_thread, registers, user_space_memory)?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::CreateMessageQueue => {
                self.syscall_create_msg_queue(current_thread, registers, user_space_memory)?;
                Ok(SysCallEffect::Return(0))
            }
            CallNumber::FreeMessageQueue => {
                self.syscall_free_msg_queue(registers)?;
                Ok(SysCallEffect::Return(0))
            }
        }
    }

    /// Look up a queue
    fn queue_by_id_checked(
        &self,
        queue_id: QueueId,
        current_process: &Arc<Process>,
    ) -> Result<Arc<MessageQueue>, Error> {
        let qu = self
            .queue_manager
            .queue_for_id(queue_id)
            .context(NotFoundSnafu {
                reason: "queue id",
                id: queue_id.get() as usize,
            })?;
        ensure!(
            qu.owner
                .upgrade()
                .is_some_and(|q| q.id == current_process.id),
            NotPermittedSnafu {
                reason: "queue not owned by current process"
            }
        );
        Ok(qu)
    }

    #[allow(clippy::unused_self)]
    fn syscall_write_log<AUST: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, AUST>,
    ) -> Result<(), Error> {
        let level = match registers.x[0] {
            1 => log::Level::Error,
            2 => log::Level::Warn,
            3 => log::Level::Info,
            4 => log::Level::Debug,
            5 => log::Level::Trace,
            _ => {
                return Err(Error::InvalidFlags {
                    reason: "unknown log level".into(),
                    bits: registers.x[0],
                })
            }
        };

        let msg_data = user_space_memory
            .check_slice::<u8>(registers.x[1].into(), registers.x[2])
            .context(InvalidAddressSnafu {
                cause: "message slice",
            })?;

        let msg = unsafe { core::str::from_utf8_unchecked(msg_data) };

        let pid = current_thread.parent.as_ref().unwrap().id;
        let tid = current_thread.id;

        log::log!(level, "({pid}:{tid}) {msg}");

        Ok(())
    }
}

#[cfg(test)]
mod tests;
