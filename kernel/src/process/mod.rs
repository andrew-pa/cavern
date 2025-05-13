//! Mechanisms for user-space processes/threads.
use alloc::sync::Arc;
use kernel_api::{ExitMessage, ExitReason};
use kernel_core::{
    collections::HandleMap,
    platform::cpu::CoreInfo,
    process::{
        system_calls::SystemCalls, Id, ManagerError, OutOfHandlesSnafu, Process, ProcessCreateInfo,
        ProcessManager, Properties, MAX_PROCESS_ID,
    },
};
use log::{debug, info, warn};
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
                supervisor_queue: info
                    .supervisor
                    .or_else(|| parent.as_ref().and_then(|p| p.props.supervisor_queue)),
                registry_queue: info
                    .registry
                    .or_else(|| parent.as_ref().and_then(|p| p.props.registry_queue)),
                privilege: info.privilege_level,
            },
            info.sections,
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

        if process.props.supervisor_queue.is_none() {
            // the root process has exited
            qemu_exit::AArch64::new().exit(match reason.tag {
                kernel_api::ExitReasonTag::User => reason.user_code,
                kernel_api::ExitReasonTag::PageFault => 1,
                kernel_api::ExitReasonTag::InvalidSysCall => 2,
                kernel_api::ExitReasonTag::Killed => 3,
            });
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
