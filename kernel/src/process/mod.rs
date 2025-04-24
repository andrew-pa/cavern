//! Mechanisms for user-space processes/threads.
use alloc::sync::Arc;
use itertools::Itertools;
use kernel_api::{ExitMessage, ExitReason, ProcessCreateInfo, KERNEL_FAKE_ID};
use kernel_core::{
    collections::HandleMap,
    memory::{page_table::MemoryProperties, PageAllocator, VirtualAddress},
    platform::cpu::CoreInfo,
    process::{
        queue::QueueManager,
        system_calls::SystemCalls,
        thread::{ProcessorState, Scheduler, State},
        Id, ManagerError, OutOfHandlesSnafu, Process, ProcessManager, Properties, Thread, ThreadId,
        MAX_PROCESS_ID,
    },
};
use log::{debug, error, warn, info, trace};
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

    fn kill_process(&self, process: &Arc<Process>, reason: ExitReason) {
        assert!(process.threads.read().is_empty());
        assert!(process.owned_queues.lock().is_empty());
        self.processes.remove(process.id);

        let msg = ExitMessage::process(process.id, reason);
        for qu in process.exit_subscribers.lock().drain(..) {
            if let Err(e) = qu.send(bytemuck::bytes_of(&msg), core::iter::empty()) {
                warn!(
                    "failed to send exit notification {:?} to queue #{}: {}",
                    msg,
                    qu.id,
                    snafu::Report::from_error(e)
                );
            }
        }

        // the process will free all owned memory (including thread stacks) when dropped
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
