//! System calls from user space.
use alloc::sync::Arc;
use bytemuck::Contiguous;
use kernel_api::{CallNumber, EnvironmentValue, ErrorCode};
use log::{debug, trace};
use snafu::Snafu;

use crate::memory::PageAllocator;

use super::{thread::Registers, ProcessManager, Thread};

/// Errors that can arise during a system call.
#[derive(Debug, Snafu)]
pub enum Error {}

impl Error {
    /// Convert the `Error` to a error code that can be returned to user space.
    #[must_use]
    pub fn to_code(self) -> ErrorCode {
        match self {}
    }
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
            process_manager,
            page_allocator,
        }
    }

    /// Execute a system call on behalf of a process.
    ///
    /// # Errors
    /// Returns an error if the system call is unsuccessful.
    pub fn dispatch_system_call(
        &self,
        syscall_number: CallNumber,
        current_thread: &Arc<Thread>,
        registers: &Registers,
    ) -> Result<usize, Error> {
        match syscall_number {
            CallNumber::ReadEnvValue => Ok(EnvironmentValue::from_integer(registers.x[0])
                .map_or(0, |v| self.syscall_read_env_value(current_thread, v))),
            CallNumber::ExitCurrentThread => self
                .syscall_exit_current_thread(current_thread, registers.x[0] as u32)
                .map(|()| 0),
            _ => todo!("implement {:?}", syscall_number),
        }
    }

    fn syscall_read_env_value(
        &self,
        current_thread: &Arc<Thread>,
        value_to_read: EnvironmentValue,
    ) -> usize {
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

    fn syscall_exit_current_thread(
        &self,
        current_thread: &Arc<Thread>,
        code: u32,
    ) -> Result<(), Error> {
        debug!("thread #{} exited with code 0x{code:x}", current_thread.id);
        todo!()
    }
}
