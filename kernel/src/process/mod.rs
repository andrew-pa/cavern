//! Mechanisms for user-space processes/threads.
use alloc::sync::Arc;
use kernel_core::{
    collections::HandleMap,
    memory::VirtualAddress,
    platform::cpu::CoreInfo,
    process::{
        thread::{ProcessorState, Scheduler, State},
        Id, Image, OutOfHandlesSnafu, Process, ProcessManager, ProcessManagerError, Properties,
        Thread, ThreadId, MAX_PROCESS_ID,
    },
};
use snafu::OptionExt;
use spin::Once;

use crate::memory::page_allocator;

pub mod thread;

/// The system process manager instance.
pub static PROCESS_MANAGER: Once<SystemProcessManager> = Once::new();

/// The system process manager instance.
pub struct SystemProcessManager {
    processes: HandleMap<Process>,
}

impl ProcessManager for SystemProcessManager {
    fn spawn_process(
        &self,
        image: &Image,
        properties: Properties,
    ) -> Result<Arc<Process>, ProcessManagerError> {
        let id = self
            .processes
            .preallocate_handle()
            .context(OutOfHandlesSnafu)?;
        let proc = Arc::new(Process::new(
            page_allocator(),
            id,
            properties,
            image.sections,
        )?);
        self.processes.insert_with_handle(id, proc.clone());

        // spawn the main thread
        self.spawn_thread(proc.clone(), image.entry_point)?;

        Ok(proc)
    }

    fn spawn_thread(
        &self,
        parent_process: Arc<Process>,
        entry_point: VirtualAddress,
    ) -> Result<Arc<Thread>, ProcessManagerError> {
        let threads = thread::THREADS.get().expect("threading initialized");
        let id = threads.preallocate_handle().context(OutOfHandlesSnafu)?;
        let pstate =
            ProcessorState::new_for_user_thread(entry_point, todo!("allocate stack for thread"));
        let thread = Arc::new(Thread::new(
            id,
            Some(parent_process),
            State::Running,
            pstate,
        ));
        {
            let ts = parent_process.threads.write();
            ts.push(thread.clone());
        }
        threads.insert_with_handle(id, thread.clone());
        thread::SCHEDULER
            .get()
            .expect("threading initialized")
            .spawn_new_thread(thread.clone());
        Ok(thread)
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

/// Initialize processes/threading.
pub fn init(cores: &[CoreInfo]) {
    thread::init(cores);
    PROCESS_MANAGER.call_once(|| SystemProcessManager {
        processes: HandleMap::new(MAX_PROCESS_ID),
    });
}
