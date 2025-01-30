//! System calls from user space.
#![allow(clippy::needless_pass_by_value)]
use alloc::{string::String, sync::Arc};
use bytemuck::Contiguous;
use kernel_api::{
    flags::ReceiveFlags, CallNumber, EnvironmentValue, ErrorCode, ExitReason, ProcessId,
    ThreadCreateInfo, ThreadId,
};
use log::{debug, error, trace, warn};
use snafu::{ensure, OptionExt, ResultExt, Snafu};

use crate::memory::{
    page_table::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker, MemoryProperties},
    PageAllocator, VirtualAddress,
};

use super::{thread::Registers, Process, ProcessManager, ProcessManagerError, Thread};

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
            Error::NotFound { .. } => ErrorCode::NotFound,
            Error::WouldBlock => ErrorCode::WouldBlock,
            Error::ProcessManager { source } => match source {
                ProcessManagerError::Memory { source } => match source {
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
                .exit_thread(current_thread, ExitReason::InvalidSysCall)
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
            _ => todo!("implement {:?}", syscall_number),
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
            EnvironmentValue::DesignatedReceiverThreadId => todo!(),
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
            .exit_thread(current_thread, ExitReason::User(code))
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
        let dst = dst_process_id
            .and_then(|pid| self.process_manager.process_for_id(pid))
            .context(NotFoundSnafu {
                reason: "destination process id",
                id: dst_process_id.map_or(0, ProcessId::get) as usize,
            })?;
        let dst_thread = dst_thread_id.and_then(|tid| self.process_manager.thread_for_id(tid));
        dst.send_message(
            (
                current_thread.parent.as_ref().unwrap().id,
                current_thread.id,
            ),
            dst_thread,
            message,
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
        let out_msg: &mut VirtualAddress = user_space_memory
            .check_mut_ref(registers.x[1].into())
            .context(InvalidAddressSnafu {
            cause: "output message ptr",
        })?;
        let out_len: &mut usize = user_space_memory
            .check_mut_ref(registers.x[2].into())
            .context(InvalidAddressSnafu {
                cause: "output message len",
            })?;
        let flags = ReceiveFlags::from_bits(flag_bits).context(InvalidFlagsSnafu {
            reason: "invalid bits",
            bits: flag_bits,
        })?;
        if let Some((msg_ptr, msg_len)) = unsafe {
            // SAFETY: it is safe to call this for the current thread, because the its page tables are current.
            current_thread.receive_message()
        } {
            *out_msg = msg_ptr;
            *out_len = msg_len;
            Ok(SysCallEffect::Return(0))
        } else if flags.contains(ReceiveFlags::NONBLOCKING) {
            Err(Error::WouldBlock)
        } else {
            current_thread.set_state(super::thread::State::Blocked);
            Ok(SysCallEffect::ScheduleNextThread)
        }
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;

    use crate::{
        memory::{page_table::MockActiveUserSpaceTables, MockPageAllocator, VirtualAddress},
        process::MockProcessManager,
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
            .withf(move |t, r| t.id == thread2.id && matches!(r, ExitReason::InvalidSysCall))
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
    fn exit_thread() {
        let pa = MockPageAllocator::new();
        let mut pm = MockProcessManager::new();

        let exit_code = 7;

        let thread = fake_thread();

        let thread2 = thread.clone();
        pm.expect_exit_thread()
            .once()
            .withf(move |t, r| {
                t.id == thread2.id && matches!(r, ExitReason::User(x) if *x == exit_code)
            })
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
}
