use alloc::sync::Arc;

use kernel_api::{ExitReason, ProcessId};
use log::debug;
use snafu::OptionExt;

use crate::{
    memory::PageAllocator,
    process::{
        queue::QueueManager,
        system_calls::NotFoundSnafu,
        thread::{Registers, ThreadManager},
        Process, ProcessManager,
    },
};

use super::{Error, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    pub(super) fn syscall_kill_process(
        &self,
        current_process: &Arc<Process>,
        registers: &Registers,
    ) -> Result<(), Error> {
        let pid = ProcessId::new(registers.x[0] as u32).context(NotFoundSnafu {
            reason: "process id is zero",
            id: 0usize,
        })?;

        let proc = self
            .process_manager
            .process_for_id(pid)
            .context(NotFoundSnafu {
                reason: "process id",
                id: pid.get() as usize,
            })?;

        // TODO: access control?
        debug!("process #{} killing process #{pid}", current_process.id);

        // Make a copy of the threads in the process. Exiting the thread will remove it from the parent process.
        let threads = proc.threads.read().clone();
        for t in threads {
            self.thread_manager.exit_thread(&t, ExitReason::killed());
        }

        // Make a copy of the queues in the process. Freeing the queue will remove it from the parent process.
        let queues = proc.owned_queues.lock().clone();
        for qu in queues {
            self.queue_manager.free_queue(&qu);
        }

        self.process_manager
            .kill_process(&proc, ExitReason::killed());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use std::assert_matches::assert_matches;

    use kernel_api::{CallNumber, ProcessId};
    use mockall::predicate::eq;

    use crate::{
        memory::active_user_space_tables::AlwaysValidActiveUserSpaceTables,
        process::{
            queue::MockQueueManager, system_calls::SysCallEffect, tests::PAGE_ALLOCATOR,
            thread::MockThreadManager, MockProcessManager, Properties, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn normal_kill_process() {
        let mut pm = MockProcessManager::new();
        let mut tm = MockThreadManager::new();

        let parent_proc = crate::process::tests::create_test_process(
            ProcessId::new(30).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(31).unwrap(),
        )
        .unwrap();

        let target_thread_id = ThreadId::new(41).unwrap();
        let target_proc = crate::process::tests::create_test_process(
            ProcessId::new(40).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            target_thread_id,
        )
        .unwrap();
        let target_proc2 = target_proc.clone();
        let target_proc_id = target_proc.id;

        pm.expect_process_for_id()
            .with(eq(target_proc_id))
            .return_once(move |_| Some(target_proc2));
        pm.expect_kill_process()
            .withf(move |p, r| p.id == target_proc_id && *r == ExitReason::killed())
            .return_once(|_, _| ());

        tm.expect_exit_thread()
            .withf(move |t, r| t.id == target_thread_id && *r == ExitReason::killed())
            .return_once(|_, _| true);

        let pa = &*PAGE_ALLOCATOR;
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut registers = Registers::default();
        registers.x[0] = target_proc.id.get() as usize;

        let current_thread = parent_proc.threads.read().first().unwrap().clone();
        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::KillProcess.into_integer(),
                &current_thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
    }

    #[test]
    fn kill_process_not_found() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(310).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(311).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        // Process manager returns None for unknown pid.
        let mut pm = MockProcessManager::new();
        pm.expect_process_for_id().return_const(None);
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = 0xdead_beef; // non-existent pid

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::KillProcess.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::NotFound { .. })
        );
    }
}
