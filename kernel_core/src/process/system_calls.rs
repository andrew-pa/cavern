//! System calls from user space.

use snafu::Snafu;

use super::{thread::Registers, ProcessManager};

/// Errors that can arise during a system call.
#[derive(Debug, Snafu)]
pub enum Error {}

impl Error {
    /// Convert the `Error` to a error code that can be returned to user space.
    #[must_use]
    pub fn to_code(self) -> usize {
        match self {}
    }
}

/// System call handler policy.
pub struct SystemCalls<'pm, PM: ProcessManager> {
    process_manager: &'pm PM,
}

impl<'pm, PM: ProcessManager> SystemCalls<'pm, PM> {
    /// Create a new system call handler policy.
    pub fn new(process_manager: &'pm PM) -> Self {
        Self { process_manager }
    }

    /// Execute a system call on behalf of a process.
    ///
    /// # Errors
    /// Returns an error if the system call is unsuccessful.
    pub fn dispatch_system_call(
        &self,
        syscall_number: u16,
        registers: &Registers,
    ) -> Result<usize, Error> {
        todo!()
    }
}
