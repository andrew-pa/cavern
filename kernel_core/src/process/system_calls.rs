//! System calls from user space.
use alloc::sync::Arc;
use bytemuck::Contiguous;
use kernel_api::{CallNumber, EnvironmentValue, ErrorCode, ExitReason};
use log::{debug, trace, warn};
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
    /// - [`SysCallEffect::ScheduleNextThread`] to cause a different thread to be scheduled. This
    /// may mean that the current thread was killed by this system call, either intentionally or
    /// due to a fault (for example, because an invalid system call number was provided).
    ///
    /// # Errors
    /// Returns an error that should be reported to user-space if the system call is unsuccessful.
    pub fn dispatch_system_call(
        &self,
        syscall_number: u16,
        current_thread: &Arc<Thread>,
        registers: &Registers,
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
        match syscall_number {
            CallNumber::ReadEnvValue => Ok(SysCallEffect::Return(
                EnvironmentValue::from_integer(registers.x[0])
                    .map_or(0, |v| self.syscall_read_env_value(current_thread, v)),
            )),
            CallNumber::ExitCurrentThread => {
                self.syscall_exit_current_thread(current_thread, registers.x[0] as u32);
                Ok(SysCallEffect::ScheduleNextThread)
            }
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

    fn syscall_exit_current_thread(&self, current_thread: &Arc<Thread>, code: u32) {
        debug!("thread #{} exited with code 0x{code:x}", current_thread.id);
        self.process_manager
            .exit_thread(current_thread, ExitReason::User(code))
            // It's very unlikely `kill_thread` will fail, and if it does the system is probably corrupt.
            .expect("failed to kill thread");
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;

    use crate::{
        memory::{MockPageAllocator, VirtualAddress},
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

        let registers = Registers::default();

        let system_call_number_that_is_invalid = 1;
        assert!(matches!(
            policy.dispatch_system_call(system_call_number_that_is_invalid, &thread, &registers),
            Ok(SysCallEffect::ScheduleNextThread)
        ));
    }

    #[test]
    fn read_current_thread_id() {
        let pa = MockPageAllocator::new();
        let pm = MockProcessManager::new();

        let thread = fake_thread();

        let policy = SystemCalls::new(&pa, &pm);

        let mut registers = Registers::default();
        registers.x[0] = EnvironmentValue::CurrentThreadId.into_integer();

        assert!(matches!(
            policy.dispatch_system_call(CallNumber::ReadEnvValue.into_integer(), &thread, &registers),
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

        let mut registers = Registers::default();
        registers.x[0] = exit_code as usize;

        assert!(matches!(
            policy.dispatch_system_call(
                CallNumber::ExitCurrentThread.into_integer(),
                &thread,
                &registers
            ),
            Ok(SysCallEffect::ScheduleNextThread)
        ));
    }
}
