//! System calls from user space.
#![allow(clippy::needless_pass_by_value)]

use alloc::{string::String, sync::Arc};
use bytemuck::Contiguous;
use kernel_api::{
    flags::{ExitNotificationSubscriptionFlags, FreeMessageFlags, ReceiveFlags},
    CallNumber, EnvironmentValue, ErrorCode, ExitReason, Message, ProcessId,
    SharedBufferCreateInfo, ThreadCreateInfo, ThreadId,
};
use log::{debug, error, trace, warn};
use snafu::{ensure, OptionExt, ResultExt, Snafu};

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        page_table::MemoryProperties,
        PageAllocator, VirtualAddress, VirtualPointer,
    },
    process::SharedBuffer,
};

use super::{
    thread::Registers, Process, ProcessManager, ProcessManagerError, SharedBufferId, Thread,
    TransferError,
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
    /// Error occurred in the process manager mechanism.
    ProcessManager {
        /// Underlying error.
        source: ProcessManagerError,
    },
    /// Receiving a message would otherwise block the thread.
    WouldBlock,
    /// Error occured doing a shared buffer transfer.
    Transfer {
        /// Underlying error.
        source: TransferError,
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
            Error::ProcessManager { source } => match source {
                ProcessManagerError::Memory { source, .. } => match source {
                    crate::memory::Error::OutOfMemory => ErrorCode::OutOfMemory,
                    crate::memory::Error::InvalidSize => ErrorCode::InvalidLength,
                    crate::memory::Error::UnknownPtr => ErrorCode::InvalidPointer,
                },
                ProcessManagerError::PageTables { .. } => ErrorCode::InvalidPointer,
                ProcessManagerError::Missing { cause } => {
                    error!("Missing value in process manager: {cause}");
                    ErrorCode::NotFound
                }
                ProcessManagerError::OutOfHandles => ErrorCode::OutOfHandles,
                ProcessManagerError::InboxFull => ErrorCode::InboxFull,
            },
            Error::Transfer { source } => match source {
                TransferError::OutOfBounds => ErrorCode::OutOfBounds,
                TransferError::InsufficentPermissions => ErrorCode::InsufficentPermissions,
                TransferError::PageTables { .. } => ErrorCode::InvalidPointer,
            },
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
pub struct SystemCalls<'pa, 'pm, PA: PageAllocator, PM: ProcessManager> {
    page_allocator: &'pa PA,
    process_manager: &'pm PM,
}

impl<'pa, 'pm, PA: PageAllocator, PM: ProcessManager> SystemCalls<'pa, 'pm, PA, PM> {
    /// Create a new system call handler policy.
    pub fn new(page_allocator: &'pa PA, process_manager: &'pm PM) -> Self {
        Self {
            page_allocator,
            process_manager,
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
            self.process_manager
                .exit_thread(current_thread, ExitReason::invalid_syscall())
                .expect("kill thread that made invalid system call");
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
            CallNumber::SetDesignatedReceiver => {
                self.syscall_set_designated_receiver(current_thread, registers)?;
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
        }
    }

    fn syscall_read_env_value(&self, current_thread: &Arc<Thread>, registers: &Registers) -> usize {
        let Some(value_to_read) = EnvironmentValue::from_integer(registers.x[0]) else {
            return 0;
        };
        trace!(
            "reading value {value_to_read:?} for thread {}",
            current_thread.id
        );
        match value_to_read {
            EnvironmentValue::CurrentProcessId => current_thread
                .parent
                .as_ref()
                .map_or(0, |p| p.id.get() as usize),
            EnvironmentValue::CurrentThreadId => current_thread.id.get() as usize,
            EnvironmentValue::DesignatedReceiverThreadId => current_thread
                .parent
                .as_ref()
                .and_then(|p| p.threads.read().first().map(|t| t.id.get()))
                .unwrap_or(0) as usize,
            EnvironmentValue::CurrentSupervisorId => current_thread
                .parent
                .as_ref()
                .and_then(|p| p.props.supervisor.as_ref())
                .map_or(0, |p| p.id.get() as usize),
            EnvironmentValue::PageSizeInBytes => self.page_allocator.page_size().into(),
        }
    }

    fn syscall_exit_current_thread(&self, current_thread: &Arc<Thread>, registers: &Registers) {
        let code: u32 = registers.x[0] as _;
        debug!("thread #{} exited with code 0x{code:x}", current_thread.id);
        self.process_manager
            .exit_thread(current_thread, ExitReason::user(code))
            // It's very unlikely `kill_thread` will fail, and if it does the system is probably corrupt.
            .expect("failed to kill thread");
    }

    fn syscall_spawn_thread<T: ActiveUserSpaceTables>(
        &self,
        parent: Arc<Process>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, T>,
    ) -> Result<(), Error> {
        let info: &ThreadCreateInfo =
            user_space_memory
                .check_ref(registers.x[0].into())
                .context(InvalidAddressSnafu {
                    cause: "thread info",
                })?;
        let out_thread_id = user_space_memory
            .check_mut_ref(registers.x[1].into())
            .context(InvalidAddressSnafu {
                cause: "output thread id",
            })?;

        let entry_ptr = VirtualAddress::from(info.entry as *mut ());
        ensure!(
            !entry_ptr.is_null(),
            InvalidPointerSnafu {
                reason: "thread entry point ptr",
                ptr: entry_ptr
            }
        );
        ensure!(
            info.stack_size > 0,
            InvalidLengthSnafu {
                reason: "stack size <= 0",
                length: info.stack_size
            }
        );

        debug!("spawning thread {info:?} in process #{}", parent.id);

        let thread = self
            .process_manager
            .spawn_thread(parent, entry_ptr, info.stack_size, info.user_data)
            .context(ProcessManagerSnafu)?;

        *out_thread_id = thread.id;

        Ok(())
    }

    fn syscall_spawn_process<T: ActiveUserSpaceTables>(
        &self,
        parent: Arc<Process>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, T>,
    ) -> Result<(), Error> {
        let info =
            user_space_memory
                .check_ref(registers.x[0].into())
                .context(InvalidAddressSnafu {
                    cause: "process info",
                })?;
        let out_process_id = user_space_memory
            .check_mut_ref(registers.x[1].into())
            .context(InvalidAddressSnafu {
                cause: "output process id",
            })?;
        debug!("spawning process {info:?}, parent #{}", parent.id);
        let proc = self
            .process_manager
            .spawn_process(Some(parent), info)
            .context(ProcessManagerSnafu)?;
        *out_process_id = proc.id;
        Ok(())
    }

    fn syscall_kill_process(
        &self,
        current_process: &Arc<Process>,
        registers: &Registers,
    ) -> Result<(), Error> {
        let pid = ProcessId::new(registers.x[0] as u32).context(NotFoundSnafu {
            reason: "process id is zero",
            id: 0usize,
        })?;

        let proc = self
            .process_manager
            .process_for_id(pid)
            .context(NotFoundSnafu {
                reason: "process id",
                id: pid.get() as usize,
            })?;

        // TODO: access control?
        debug!("process #{} killing process #{pid}", current_process.id);

        self.process_manager
            .kill_process(&proc)
            .context(ProcessManagerSnafu)?;

        Ok(())
    }

    fn syscall_allocate_heap_pages<T: ActiveUserSpaceTables>(
        &self,
        current_process: &Arc<Process>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, T>,
    ) -> Result<(), Error> {
        let size: usize = registers.x[0];
        let dst: &mut usize = user_space_memory
            .check_mut_ref(registers.x[1].into())
            .context(InvalidAddressSnafu {
                cause: "output pointer",
            })?;

        debug!(
            "allocating {size} pages for process #{}",
            current_process.id
        );

        let addr = current_process
            .allocate_memory(
                self.page_allocator,
                size,
                MemoryProperties {
                    user_space_access: true,
                    writable: true,
                    executable: true,
                    ..Default::default()
                },
            )
            .context(ProcessManagerSnafu)?;

        *dst = addr.into();

        Ok(())
    }

    fn syscall_free_heap_pages(
        &self,
        current_process: &Arc<Process>,
        registers: &Registers,
    ) -> Result<(), Error> {
        let ptr: VirtualAddress = registers.x[0].into();
        let size: usize = registers.x[1];
        debug!(
            "freeing {size} pages @ {ptr:?} for process #{}",
            current_process.id
        );
        current_process
            .free_memory(self.page_allocator, ptr, size)
            .context(ProcessManagerSnafu)
    }

    fn syscall_send<T: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, T>,
    ) -> Result<(), Error> {
        let dst_process_id: Option<ProcessId> = ProcessId::new(registers.x[0] as _);
        let dst_thread_id: Option<ThreadId> = ThreadId::new(registers.x[1] as _);
        let message = user_space_memory
            .check_slice(registers.x[2].into(), registers.x[3])
            .context(InvalidAddressSnafu { cause: "message" })?;
        let buffers: &[SharedBufferCreateInfo] = user_space_memory
            .check_slice(registers.x[4].into(), registers.x[5])
            .context(InvalidAddressSnafu { cause: "buffers" })?;
        trace!("sending buffers {buffers:?}");
        let dst = dst_process_id
            .and_then(|pid| self.process_manager.process_for_id(pid))
            .context(NotFoundSnafu {
                reason: "destination process id",
                id: dst_process_id.map_or(0, ProcessId::get) as usize,
            })?;
        let dst_thread = dst_thread_id.and_then(|tid| self.process_manager.thread_for_id(tid));
        let current_proc = current_thread.parent.as_ref().unwrap();
        dst.send_message(
            (
                current_thread.parent.as_ref().unwrap().id,
                current_thread.id,
            ),
            dst_thread,
            message,
            buffers.iter().map(|b| {
                Arc::new(SharedBuffer {
                    owner: current_proc.clone(),
                    flags: b.flags,
                    base_address: VirtualAddress::from(b.base_address.cast()),
                    length: b.length,
                })
            }),
        )
        .context(ProcessManagerSnafu)
    }

    #[allow(clippy::unused_self)]
    fn syscall_receive<T: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, T>,
    ) -> Result<SysCallEffect, Error> {
        let flag_bits: usize = registers.x[0];
        let u_out_msg = registers.x[1].into();
        let out_msg: &mut VirtualAddress =
            user_space_memory
                .check_mut_ref(u_out_msg)
                .context(InvalidAddressSnafu {
                    cause: "output message ptr",
                })?;
        let u_out_len = registers.x[2].into();
        let out_len: &mut usize =
            user_space_memory
                .check_mut_ref(u_out_len)
                .context(InvalidAddressSnafu {
                    cause: "output message len",
                })?;
        let flags = ReceiveFlags::from_bits(flag_bits).context(InvalidFlagsSnafu {
            reason: "invalid bits",
            bits: flag_bits,
        })?;
        if let Some((msg_ptr, msg_len)) = unsafe {
            // SAFETY: it is safe to call this for the current thread, because the its page tables are current.
            current_thread.receive_message_immediately()
        } {
            *out_msg = msg_ptr;
            *out_len = msg_len;
            Ok(SysCallEffect::Return(0))
        } else if flags.contains(ReceiveFlags::NONBLOCKING) {
            Err(Error::WouldBlock)
        } else {
            current_thread.wait_for_message(u_out_msg, u_out_len);
            Ok(SysCallEffect::ScheduleNextThread)
        }
    }

    #[allow(clippy::unused_self)]
    fn syscall_transfer_to<AUST: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, AUST>,
    ) -> Result<(), Error> {
        let proc = current_thread.parent.as_ref().unwrap();
        let buffer_handle =
            SharedBufferId::new(registers.x[0] as u32).context(InvalidHandleSnafu {
                reason: "buffer handle is zero",
                handle: 0u32,
            })?;
        let buf = proc
            .shared_buffers
            .get(buffer_handle)
            .context(InvalidHandleSnafu {
                reason: "buffer handle not found",
                handle: buffer_handle.get(),
            })?;
        let offset = registers.x[1];
        let src = user_space_memory
            .check_slice(registers.x[2].into(), registers.x[3])
            .context(InvalidAddressSnafu {
                cause: "source buffer",
            })?;
        buf.transfer_to(offset, src).context(TransferSnafu)
    }

    #[allow(clippy::unused_self)]
    fn syscall_transfer_from<AUST: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, AUST>,
    ) -> Result<(), Error> {
        let proc = current_thread.parent.as_ref().unwrap();
        let buffer_handle =
            SharedBufferId::new(registers.x[0] as u32).context(InvalidHandleSnafu {
                reason: "buffer handle is zero",
                handle: 0u32,
            })?;
        let buf = proc
            .shared_buffers
            .get(buffer_handle)
            .context(InvalidHandleSnafu {
                reason: "buffer handle not found",
                handle: buffer_handle.get(),
            })?;
        let offset = registers.x[1];
        let dst = user_space_memory
            .check_slice_mut(registers.x[2].into(), registers.x[3])
            .context(InvalidAddressSnafu {
                cause: "destination buffer",
            })?;
        buf.transfer_from(offset, dst).context(TransferSnafu)
    }

    #[allow(clippy::unused_self)]
    fn syscall_set_designated_receiver(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
    ) -> Result<(), Error> {
        let target_thread_id =
            ThreadId::new(registers.x[0] as u32).context(InvalidHandleSnafu {
                reason: "thread id",
                handle: registers.x[0] as u32,
            })?;
        let proc = current_thread.parent.as_ref().unwrap();
        let mut threads = proc.threads.write();
        let i = threads
            .iter()
            .position(|t| t.id == target_thread_id)
            .context(InvalidHandleSnafu {
                reason: "thread not in process",
                handle: target_thread_id.get(),
            })?;
        threads.swap(0, i);
        Ok(())
    }

    fn syscall_free_message<AUST: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, AUST>,
    ) -> Result<(), Error> {
        let flags = FreeMessageFlags::from_bits(registers.x[0]).context(InvalidFlagsSnafu {
            reason: "invalid bits",
            bits: registers.x[0],
        })?;

        let ptr: VirtualAddress = registers.x[1].into();
        let len = registers.x[2];

        let proc = current_thread.parent.as_ref().unwrap();

        if flags.contains(FreeMessageFlags::FREE_BUFFERS) {
            let msg: &[u8] = user_space_memory
                .check_slice(VirtualPointer::from(ptr).cast(), len)
                .context(InvalidAddressSnafu { cause: "message" })?;
            let msg = unsafe { Message::from_slice(msg) };
            proc.free_shared_buffers(msg.buffers().iter().map(|b| b.buffer))
                .context(ProcessManagerSnafu)?;
        }

        proc.free_message(ptr, len).context(ProcessManagerSnafu)?;

        Ok(())
    }

    fn syscall_free_shared_buffers<AUST: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, AUST>,
    ) -> Result<(), Error> {
        let buffers: &[SharedBufferId] = user_space_memory
            .check_slice(registers.x[0].into(), registers.x[1])
            .context(InvalidAddressSnafu {
                cause: "buffers slice",
            })?;

        let proc = current_thread.parent.as_ref().unwrap();

        proc.free_shared_buffers(buffers.iter().copied())
            .context(ProcessManagerSnafu)
    }

    fn syscall_exit_notification_subscription(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
    ) -> Result<(), Error> {
        let flags = ExitNotificationSubscriptionFlags::from_bits(registers.x[0]).context(
            InvalidFlagsSnafu {
                reason: "invalid flag bits",
                bits: registers.x[0],
            },
        )?;

        ensure!(
            !flags.contains(
                ExitNotificationSubscriptionFlags::PROCESS
                    | ExitNotificationSubscriptionFlags::THREAD
            ) && !flags.is_empty(),
            InvalidFlagsSnafu {
                reason: "process mode xor thread mode",
                bits: registers.x[0]
            }
        );

        let current_proc = current_thread.parent.as_ref().unwrap();

        let receiver_tid = if let Some(tid) = ThreadId::new(registers.x[2] as u32) {
            ensure!(
                current_proc.threads.read().iter().any(|t| t.id == tid),
                NotFoundSnafu {
                    reason: "receiver thread not in process",
                    id: registers.x[2]
                }
            );
            Some(tid)
        } else {
            None
        };

        let process_subscription = |exit_subs: &mut alloc::vec::Vec<_>| {
            if flags.contains(ExitNotificationSubscriptionFlags::UNSUBSCRIBE) {
                exit_subs.retain_mut(|(pid, tid)| {
                    *pid != current_proc.id
                        && match (tid, receiver_tid) {
                            (Some(a), Some(b)) => *a != b,
                            (None, None) => false,
                            _ => true,
                        }
                });
            } else {
                let sub = (current_proc.id, receiver_tid);
                if !exit_subs.contains(&sub) {
                    exit_subs.push(sub);
                }
            }
        };

        if flags.contains(ExitNotificationSubscriptionFlags::PROCESS) {
            let proc = ProcessId::new(registers.x[1] as u32)
                .and_then(|id| self.process_manager.process_for_id(id))
                .context(InvalidHandleSnafu {
                    reason: "process id unknown",
                    handle: registers.x[1] as u32,
                })?;
            debug!(
                "subscribing process #{}, thread #{:?} to exit of process #{}",
                current_proc.id, receiver_tid, proc.id
            );
            let mut s = proc.exit_subscribers.lock();
            process_subscription(&mut s);
        } else if flags.contains(ExitNotificationSubscriptionFlags::THREAD) {
            let thread = ThreadId::new(registers.x[1] as u32)
                .and_then(|id| self.process_manager.thread_for_id(id))
                .context(InvalidHandleSnafu {
                    reason: "thread id unknown",
                    handle: registers.x[1] as u32,
                })?;
            debug!(
                "subscribing process #{}, thread #{:?} to exit of thread #{}",
                current_proc.id, receiver_tid, thread.id
            );
            let mut s = thread.exit_subscribers.lock();
            process_subscription(&mut s);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::{mem::MaybeUninit, num::NonZeroU32};
    use std::vec::Vec;

    use kernel_api::{flags::SharedBufferFlags, MessageHeader, SharedBufferInfo};
    use mockall::{predicate::eq, Sequence};

    use crate::{
        memory::{
            active_user_space_tables::{
                AlwaysValidActiveUserSpaceTables, MockActiveUserSpaceTables,
            },
            MockPageAllocator, PageSize, VirtualAddress, VirtualPointerMut,
        },
        process::{
            tests::PAGE_ALLOCATOR,
            thread::{ProcessorState, State},
            MockProcessManager, PendingMessage, Properties,
        },
    };

    use super::*;

    fn fake_thread() -> Arc<Thread> {
        Arc::new(Thread::new(
            NonZeroU32::new(777).unwrap(),
            None,
            crate::process::thread::State::Running,
            crate::process::thread::ProcessorState::new_for_user_thread(
                VirtualAddress::null(),
                VirtualAddress::null(),
                0,
            ),
            (VirtualAddress::null(), 0),
        ))
    }

    #[test]
    fn invalid_syscall_number() {
        let pa = MockPageAllocator::new();
        let mut pm = MockProcessManager::new();

        let thread = fake_thread();

        // invalid syscall number -> thread fault
        let thread2 = thread.clone();
        pm.expect_exit_thread()
            .once()
            .withf(move |t, r| t.id == thread2.id && *r == ExitReason::invalid_syscall())
            .returning(|_, _| Ok(()));

        let policy = SystemCalls::new(&pa, &pm);

        let usm = MockActiveUserSpaceTables::new();

        let registers = Registers::default();

        let system_call_number_that_is_invalid = 1;
        assert!(matches!(
            policy.dispatch_system_call(
                system_call_number_that_is_invalid,
                &thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::ScheduleNextThread)
        ));
    }

    #[test]
    fn read_current_thread_id() {
        let pa = MockPageAllocator::new();
        let pm = MockProcessManager::new();

        let thread = fake_thread();

        let policy = SystemCalls::new(&pa, &pm);

        let usm = MockActiveUserSpaceTables::new();

        let mut registers = Registers::default();
        registers.x[0] = EnvironmentValue::CurrentThreadId.into_integer();

        assert!(matches!(
            policy.dispatch_system_call(CallNumber::ReadEnvValue.into_integer(), &thread, &registers, &usm),
            Ok(SysCallEffect::Return(x)) if x as u32 == thread.id.get()
        ));
    }

    #[test]
    fn normal_exit_thread() {
        let pa = MockPageAllocator::new();
        let mut pm = MockProcessManager::new();

        let exit_code = 7;

        let thread = fake_thread();

        let thread2 = thread.clone();
        pm.expect_exit_thread()
            .once()
            .withf(move |t, r| t.id == thread2.id && *r == ExitReason::user(exit_code))
            .returning(|_, _| Ok(()));

        let policy = SystemCalls::new(&pa, &pm);

        let usm = MockActiveUserSpaceTables::new();

        let mut registers = Registers::default();
        registers.x[0] = exit_code as usize;

        assert!(matches!(
            policy.dispatch_system_call(
                CallNumber::ExitCurrentThread.into_integer(),
                &thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::ScheduleNextThread)
        ));
    }

    #[test]
    fn normal_spawn_thread() {
        fn test_entry(_: usize) -> ! {
            unreachable!()
        }

        let mut pm = MockProcessManager::new();

        let proc = crate::process::tests::create_test_process(
            ProcessId::new(7).unwrap(),
            crate::process::Properties {
                supervisor: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(8).unwrap(),
        )
        .unwrap();

        let new_thread = Arc::new(Thread::new(
            ThreadId::new(9).unwrap(),
            Some(proc.clone()),
            State::Running,
            ProcessorState::new_for_user_thread(VirtualAddress::null(), VirtualAddress::null(), 0),
            (VirtualAddress::null(), 0),
        ));

        let info = ThreadCreateInfo {
            entry: test_entry,
            stack_size: 100,
            user_data: 777,
        };
        let info_ptr = &raw const info;

        let mut thread_id = 0;
        let thread_id_ptr = &raw mut thread_id;

        let pid = proc.id;
        pm.expect_spawn_thread()
            .with(
                mockall::predicate::function(move |p: &Arc<Process>| p.id == pid),
                eq(VirtualAddress::from(test_entry as usize)),
                eq(info.stack_size),
                eq(info.user_data),
            )
            .return_once(|_, _, _, _| Ok(new_thread));

        let mut registers = Registers::default();
        registers.x[0] = info_ptr as _;
        registers.x[1] = thread_id_ptr as _;

        let th = proc.threads.read().first().unwrap().clone();

        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert!(matches!(
            policy.dispatch_system_call(
                CallNumber::SpawnThread.into_integer(),
                &th,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        ));

        assert_eq!(thread_id, 9);
    }

    #[test]
    fn normal_send() {
        let sender_proc = crate::process::tests::create_test_process(
            ProcessId::new(7).unwrap(),
            Properties {
                supervisor: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(80).unwrap(),
        )
        .unwrap();
        let receiver_proc = crate::process::tests::create_test_process(
            ProcessId::new(8).unwrap(),
            Properties {
                supervisor: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(81).unwrap(),
        )
        .unwrap();

        let message = b"Hello, world!!";
        let buffers = &[SharedBufferCreateInfo {
            flags: SharedBufferFlags::READ,
            base_address: 0x1fff as _,
            length: 1234,
        }];

        let mut pm = MockProcessManager::new();

        let receiver_proc2 = receiver_proc.clone();
        pm.expect_process_for_id()
            .with(eq(receiver_proc.id))
            .return_once(move |_| Some(receiver_proc2));

        let mut registers = Registers::default();
        registers.x[0] = receiver_proc.id.get() as usize;
        registers.x[1] = 0; // use the designated receiver thread
        registers.x[2] = message.as_ptr() as usize;
        registers.x[3] = message.len();
        registers.x[4] = buffers.as_ptr() as usize;
        registers.x[5] = buffers.len();

        let th = sender_proc.threads.read().first().unwrap().clone();

        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert!(matches!(
            policy.dispatch_system_call(CallNumber::Send.into_integer(), &th, &registers, &usm),
            Ok(SysCallEffect::Return(0))
        ));

        let thread = receiver_proc.threads.read().first().cloned().unwrap();
        let msg = thread.inbox_queue.pop().unwrap();
        assert_eq!(
            msg.data_length,
            message.len() + size_of::<MessageHeader>() + size_of::<SharedBufferInfo>()
        );
        assert_eq!(msg.sender_process_id, sender_proc.id);
        assert_eq!(msg.sender_thread_id, th.id);

        let buf_hdl = msg
            .buffer_handles
            .first()
            .cloned()
            .expect("message has shared buffer");
        let buf = receiver_proc
            .shared_buffers
            .get(buf_hdl)
            .expect("get buffer by handle");
        assert_eq!(buf.owner.id, sender_proc.id);
        assert!(buf.flags.symmetric_difference(buffers[0].flags).is_empty());
        assert_eq!(buf.base_address, (buffers[0].base_address as usize).into());
        assert_eq!(buf.length, buffers[0].length);

        let mut message_data_check = [0u8; 14];
        unsafe {
            receiver_proc
                .page_tables
                .read()
                .copy_from_while_unmapped(
                    msg.data_address
                        .byte_add(size_of::<MessageHeader>() + size_of::<SharedBufferInfo>()),
                    &mut message_data_check,
                )
                .unwrap();
        }
        assert_eq!(&message_data_check, message);
    }

    #[test]
    fn normal_receive_would_block() {
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(7).unwrap(),
            Properties {
                supervisor: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(80).unwrap(),
        )
        .unwrap();

        let pm = MockProcessManager::new();

        let mut registers = Registers::default();
        registers.x[0] = ReceiveFlags::NONBLOCKING.bits();
        registers.x[1] = 0xabcd;
        registers.x[2] = 0xbcde;

        let th = proc.threads.read().first().unwrap().clone();

        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert!(matches!(
            policy.dispatch_system_call(CallNumber::Receive.into_integer(), &th, &registers, &usm),
            Err(Error::WouldBlock)
        ));
    }

    #[test]
    fn normal_receive_block() {
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(7).unwrap(),
            Properties {
                supervisor: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(80).unwrap(),
        )
        .unwrap();

        let pm = MockProcessManager::new();

        let mut registers = Registers::default();
        registers.x[0] = ReceiveFlags::empty().bits();
        registers.x[1] = 0xabcd;
        registers.x[2] = 0xbcde;

        let th = proc.threads.read().first().unwrap().clone();

        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert!(matches!(
            policy.dispatch_system_call(CallNumber::Receive.into_integer(), &th, &registers, &usm),
            Ok(SysCallEffect::ScheduleNextThread)
        ));

        assert_eq!(th.state(), State::WaitingForMessage);
        let pmr = th.pending_message_receive.lock();
        assert_eq!(*pmr, Some((0xabcd.into(), 0xbcde.into())));
    }

    #[test]
    fn normal_receive_immediate() {
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(7).unwrap(),
            Properties {
                supervisor: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(80).unwrap(),
        )
        .unwrap();
        let th = proc.threads.read().first().unwrap().clone();

        let mut message = [0u8; 64];

        th.inbox_queue.push(PendingMessage {
            data_address: VirtualPointerMut::from(message.as_mut_ptr()).cast(),
            data_length: message.len(),
            sender_process_id: ProcessId::new(123).unwrap(),
            sender_thread_id: ProcessId::new(456).unwrap(),
            buffer_handles: Vec::new(),
        });

        let pm = MockProcessManager::new();

        let mut msg_ptr: MaybeUninit<*mut ()> = MaybeUninit::uninit();
        let mut msg_len: MaybeUninit<usize> = MaybeUninit::uninit();

        let mut registers = Registers::default();
        registers.x[0] = ReceiveFlags::empty().bits();
        registers.x[1] = msg_ptr.as_mut_ptr() as usize;
        registers.x[2] = msg_len.as_mut_ptr() as usize;

        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert!(matches!(
            policy.dispatch_system_call(CallNumber::Receive.into_integer(), &th, &registers, &usm),
            Ok(SysCallEffect::Return(0))
        ));

        unsafe {
            assert_eq!(msg_ptr.assume_init(), message.as_mut_ptr() as _);
            assert_eq!(msg_len.assume_init(), message.len());
        }
        let msg = unsafe { Message::from_slice(&message) };
        assert_eq!(msg.header().sender_pid.get(), 123);
        assert_eq!(msg.header().sender_tid.get(), 456);
        assert_eq!(msg.header().num_buffers, 0);
    }
}
