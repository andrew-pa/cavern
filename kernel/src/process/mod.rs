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
        Id, ManagerError, OutOfHandlesSnafu, Process, ProcessManager, Properties, Thread, ThreadId,
        MAX_PROCESS_ID,
    },
};
use log::{debug, error, info, trace};
use qemu_exit::QEMUExit;
use queue::SystemQueueManager;
use snafu::OptionExt;
use spin::Once;
use thread::{PlatformScheduler, SystemThreadManager};

use crate::memory::{page_allocator, PlatformPageAllocator};

pub mod queue;
pub mod thread;

/// The system process manager instance.
pub static PROCESS_MANAGER: Once<SystemProcessManager> = Once::new();

/// The system process manager instance.
pub struct SystemProcessManager {
    processes: HandleMap<Process>,
}

impl SystemProcessManager {
    /// Handle a process exiting, from either being killed or from the last thread exiting.
    fn exit_process(&self, process: &Arc<Process>, reason: ExitReason) -> Result<(), ManagerError> {
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

        // if this process has no supervisor than it must be the root
        // NOTE: this is only true if the root process makes sure to set itself as the supervisor
        // for all of its children!
        if process.props.supervisor.is_none() {
            error!("root process exited! {reason:?}");

            // if we're running in QEMU, propagate the exit to the host
            let exit = qemu_exit::AArch64::new();
            match reason.tag {
                kernel_api::ExitReasonTag::User => exit.exit(reason.user_code),
                _ => exit.exit_failure(),
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
    ) -> Result<Arc<Process>, ManagerError> {
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

        Ok(proc)
    }

    fn kill_process(&self, process: &Arc<Process>) -> Result<(), ManagerError> {
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

    fn process_for_id(&self, process_id: Id) -> Option<Arc<Process>> {
        self.processes.get(process_id)
    }
}

/// The global system call handler policy instance.
pub static SYS_CALL_POLICY: Once<
    SystemCalls<
        'static,
        'static,
        PlatformPageAllocator,
        SystemProcessManager,
        SystemThreadManager<PlatformScheduler>,
        SystemQueueManager,
    >,
> = Once::new();

/// Initialize processes/threading.
pub fn init(cores: &[CoreInfo]) {
    debug!("Initalizing processes...");
    thread::init(cores);
    let pm = PROCESS_MANAGER.call_once(|| SystemProcessManager {
        processes: HandleMap::new(MAX_PROCESS_ID),
    });
    queue::init();
    SYS_CALL_POLICY.call_once(|| {
        SystemCalls::new(
            page_allocator(),
            pm,
            thread::THREAD_MANAGER.get().unwrap(),
            queue::QUEUE_MANAGER.get().unwrap(),
        )
    });
    info!("Processes initialized!");
}
