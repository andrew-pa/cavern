//! Mechanisms for user-space processes/threads.
use alloc::sync::Arc;
use itertools::Itertools;
use kernel_api::ExitReason;
use kernel_core::{
    collections::HandleMap,
    memory::{page_table::MemoryProperties, PageAllocator, VirtualAddress},
    platform::cpu::CoreInfo,
    process::{
        system_calls::SystemCalls,
        thread::{ProcessorState, Scheduler, State},
        Id, Image, OutOfHandlesSnafu, Process, ProcessManager, ProcessManagerError, Properties,
        Thread, ThreadId, MAX_PROCESS_ID,
    },
};
use log::{debug, trace};
use snafu::OptionExt;
use spin::Once;

use crate::memory::{page_allocator, PlatformPageAllocator};

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
        debug!("spawning process #{id}");
        let proc = Arc::new(Process::new(
            page_allocator(),
            id,
            properties,
            image.sections,
        )?);
        self.processes.insert_with_handle(id, proc.clone());

        // spawn the main thread with an 8 MiB stack
        self.spawn_thread(
            proc.clone(),
            image.entry_point,
            8 * 1024 * 1024 / page_allocator().page_size(),
        )?;

        Ok(proc)
    }

    fn spawn_thread(
        &self,
        parent_process: Arc<Process>,
        entry_point: VirtualAddress,
        stack_size: usize,
    ) -> Result<Arc<Thread>, ProcessManagerError> {
        let physical_entry = parent_process
            .page_tables
            .read()
            .physical_address_of(entry_point);
        debug!("physical entry point address = {physical_entry:?}");

        let threads = thread::THREADS.get().expect("threading initialized");
        let id = threads.preallocate_handle().context(OutOfHandlesSnafu)?;
        trace!("spawning thread #{id}");
        let stack = parent_process.allocate_memory(
            page_allocator(),
            stack_size,
            &MemoryProperties {
                writable: true,
                executable: false,
                user_space_access: true,
                ..MemoryProperties::default()
            },
        )?;
        let stack_ptr = stack.byte_add(stack_size * page_allocator().page_size());
        let pstate = ProcessorState::new_for_user_thread(entry_point, stack_ptr);
        debug!("creating thread #{id} in process #{}, entry point @ {entry_point:?}, stack @ {stack_ptr:?}", parent_process.id);
        let thread = Arc::new(Thread::new(
            id,
            Some(parent_process.clone()),
            State::Running,
            pstate,
            (stack, stack_size),
        ));
        {
            let mut ts = parent_process.threads.write();
            ts.push(thread.clone());
        }
        threads.insert_with_handle(id, thread.clone());
        thread::SCHEDULER
            .get()
            .expect("threading initialized")
            .spawn_new_thread(thread.clone());
        Ok(thread)
    }

    fn kill_process(&self, _process: &Arc<Process>) -> Result<(), ProcessManagerError> {
        todo!()
    }

    fn exit_thread(
        &self,
        thread: &Arc<Thread>,
        reason: ExitReason,
    ) -> Result<(), ProcessManagerError> {
        debug!("thread #{} exited with reason {reason:?}", thread.id);

        // remove current thread from scheduler, set state to finished
        thread.set_state(State::Finished);

        // remove thread from parent process
        if let Some(parent) = thread.parent.as_ref() {
            let last_thread = {
                let mut ts = parent.threads.write();
                let (i, _) = ts
                    .iter()
                    .find_position(|t| t.id == thread.id)
                    .expect("find thread in parent");
                ts.swap_remove(i);
                ts.is_empty()
            };

            // free thread stack
            parent.free_memory(page_allocator(), thread.stack.0, thread.stack.1)?;

            if last_thread {
                // TODO: if this was the last thread, the parent process is now also finished
            }
            // TODO: send message to parent
        }
        // remove thread from handle table
        thread::THREADS
            .get()
            .unwrap()
            .remove(thread.id)
            .expect("thread is in thread handle table");
        Ok(())
    }

    fn thread_for_id(&self, thread_id: ThreadId) -> Option<Arc<Thread>> {
        thread::THREADS.get().unwrap().get(thread_id)
    }

    fn process_for_id(&self, process_id: Id) -> Option<Arc<Process>> {
        self.processes.get(process_id)
    }
}

/// The global system call handler policy instance.
pub static SYS_CALL_POLICY: Once<
    SystemCalls<'static, 'static, PlatformPageAllocator, SystemProcessManager>,
> = Once::new();

/// Initialize processes/threading.
pub fn init(cores: &[CoreInfo]) {
    thread::init(cores);
    let pm = PROCESS_MANAGER.call_once(|| SystemProcessManager {
        processes: HandleMap::new(MAX_PROCESS_ID),
    });
    SYS_CALL_POLICY.call_once(|| SystemCalls::new(page_allocator(), pm));
}
