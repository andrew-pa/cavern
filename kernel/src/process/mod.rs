//! Mechanisms for user-space processes/threads.
use alloc::sync::Arc;
use itertools::Itertools;
use kernel_api::{ExitMessage, ExitReason, ProcessCreateInfo, KERNEL_FAKE_ID};
use kernel_core::{
    collections::HandleMap,
    memory::{page_table::MemoryProperties, PageAllocator, VirtualAddress},
    platform::cpu::CoreInfo,
    process::{
        system_calls::SystemCalls,
        thread::{ProcessorState, Scheduler, State},
        Id, OutOfHandlesSnafu, Process, ProcessManager, ProcessManagerError, Properties, Thread,
        ThreadId, MAX_PROCESS_ID,
    },
};
use log::{debug, trace};
use snafu::OptionExt;
use spin::Once;
use thread::THREADS;

use crate::memory::{page_allocator, PlatformPageAllocator};

pub mod thread;

/// The system process manager instance.
pub static PROCESS_MANAGER: Once<SystemProcessManager> = Once::new();

/// The system process manager instance.
pub struct SystemProcessManager {
    processes: HandleMap<Process>,
}

// TODO: if the designated receiver thread exits then we should just kill the whole process?

impl SystemProcessManager {
    /// Handle a process exiting, from either being killed or from the last thread exiting.
    fn exit_process(
        &self,
        process: &Arc<Process>,
        reason: ExitReason,
    ) -> Result<(), ProcessManagerError> {
        self.processes.remove(process.id);

        let msg = ExitMessage::process(process.id, reason);
        for (pid, tid) in process.exit_subscribers.lock().iter() {
            if let Some(proc) = self.processes.get(*pid) {
                proc.send_message(
                    (KERNEL_FAKE_ID, KERNEL_FAKE_ID),
                    tid.and_then(|id| THREADS.get().unwrap().get(id)),
                    bytemuck::bytes_of(&msg),
                    core::iter::empty(),
                )?;
            }
        }

        // the process will free all owned memory (including thread stacks) when dropped
        Ok(())
    }
}

impl ProcessManager for SystemProcessManager {
    fn spawn_process(
        &self,
        parent: Option<Arc<Process>>,
        info: &ProcessCreateInfo,
    ) -> Result<Arc<Process>, ProcessManagerError> {
        let id = self
            .processes
            .preallocate_handle()
            .context(OutOfHandlesSnafu)?;
        debug!("spawning process #{id}");
        let proc = Arc::new(Process::new(
            page_allocator(),
            id,
            Properties {
                supervisor: info
                    .supervisor
                    .and_then(|sid| self.process_for_id(sid))
                    .or_else(|| parent.as_ref().and_then(|p| p.props.supervisor.clone())),
                privilege: info.privilege_level,
            },
            unsafe { core::slice::from_raw_parts(info.sections, info.num_sections) },
            info.inbox_size,
        )?);
        self.processes.insert_with_handle(id, proc.clone());

        // spawn the main thread with an 8 MiB stack
        self.spawn_thread(
            proc.clone(),
            info.entry_point.into(),
            8 * 1024 * 1024 / page_allocator().page_size(),
            0,
        )?;

        Ok(proc)
    }

    fn spawn_thread(
        &self,
        parent_process: Arc<Process>,
        entry_point: VirtualAddress,
        stack_size: usize,
        user_data: usize,
    ) -> Result<Arc<Thread>, ProcessManagerError> {
        let threads = thread::THREADS.get().expect("threading initialized");
        let id = threads.preallocate_handle().context(OutOfHandlesSnafu)?;
        trace!("spawning thread #{id}");
        let stack = parent_process.allocate_memory(
            page_allocator(),
            stack_size,
            MemoryProperties {
                writable: true,
                executable: false,
                user_space_access: true,
                ..MemoryProperties::default()
            },
        )?;
        let stack_ptr = stack.byte_add(stack_size * page_allocator().page_size());
        let pstate = ProcessorState::new_for_user_thread(entry_point, stack_ptr, user_data);
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

    fn kill_process(&self, process: &Arc<Process>) -> Result<(), ProcessManagerError> {
        for t in process.threads.write().drain(..) {
            t.set_state(State::Finished);
            thread::THREADS
                .get()
                .unwrap()
                .remove(t.id)
                .expect("thread is in thread handle table");
        }
        self.exit_process(process, ExitReason::killed())?;
        Ok(())
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
                // if this was the last thread, the parent process is now also finished
                // the "parent" will then be the process that spawned this process.
                debug!("last thread in process exited");
                self.exit_process(parent, reason)?;
            } else {
                // notify exit subscribers that a thread exited
                let msg = ExitMessage::thread(thread.id, reason);
                for (pid, tid) in thread.exit_subscribers.lock().iter() {
                    trace!("sending exit message {msg:?} to process #{pid}, thread #{tid:?}",);
                    if let Some(proc) = self.process_for_id(*pid) {
                        proc.send_message(
                            (KERNEL_FAKE_ID, KERNEL_FAKE_ID),
                            tid.and_then(|id| self.thread_for_id(id)),
                            bytemuck::bytes_of(&msg),
                            core::iter::empty(),
                        )?;
                    }
                }
            }
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
