//! Mechanisms for user-space processes/threads.
use alloc::sync::Arc;
use kernel_core::process::{
    Id, Image, Process, ProcessManager, ProcessManagerError, Properties, Thread, ThreadId,
};

pub mod thread;

// pub static PROCESSES: Once<HandleMap<Process>> = Once::new();

/// The system process manager instance.
pub struct SystemProcessManager {}

impl ProcessManager for SystemProcessManager {
    fn spawn_process(
        &self,
        image: &Image,
        properties: Properties,
    ) -> Result<Arc<Process>, ProcessManagerError> {
        todo!()
    }

    fn spawn_thread(
        &self,
        parent_process: Arc<Process>,
    ) -> Result<Arc<Thread>, ProcessManagerError> {
        todo!()
    }

    fn kill_process(&self, process: Arc<Process>) -> Result<(), ProcessManagerError> {
        todo!()
    }

    fn kill_thread(&self, thread: Arc<Thread>) -> Result<(), ProcessManagerError> {
        todo!()
    }

    fn thread_for_id(
        &self,
        thread_id: ThreadId,
    ) -> Result<Option<Arc<Thread>>, ProcessManagerError> {
        todo!()
    }

    fn process_for_id(&self, process_id: Id) -> Result<Option<Arc<Process>>, ProcessManagerError> {
        todo!()
    }
}
