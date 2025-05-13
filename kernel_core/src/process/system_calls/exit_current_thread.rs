use alloc::sync::Arc;
use kernel_api::ExitReason;
use log::debug;

use crate::{
    memory::PageAllocator,
    process::{
        kill_thread_entirely,
        queue::QueueManager,
        thread::{Registers, ThreadManager},
        ProcessManager, Thread,
    },
};

use super::SystemCalls;

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    pub(super) fn syscall_exit_current_thread(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
    ) {
        let code: u32 = registers.x[0] as _;
        debug!("thread #{} exited with code 0x{code:x}", current_thread.id);
        kill_thread_entirely(
            self.process_manager,
            self.thread_manager,
            self.queue_manager,
            current_thread,
            ExitReason::user(code),
        );
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use std::assert_matches::assert_matches;

    use kernel_api::{CallNumber, ProcessId};

    use crate::{
        memory::{
            active_user_space_tables::MockActiveUserSpaceTables, MockPageAllocator, VirtualAddress,
        },
        process::{
            queue::MockQueueManager,
            system_calls::{tests::fake_thread, SysCallEffect},
            thread::{MockThreadManager, ProcessorState, State},
            MockProcessManager, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn normal_exit_thread() {
        let pa = MockPageAllocator::new();
        let pm = MockProcessManager::new();
        let mut tm = MockThreadManager::new();
        let qm = MockQueueManager::new();

        let exit_code = 7;

        let thread = fake_thread();

        let thread2 = thread.clone();
        tm.expect_exit_thread()
            .once()
            .withf(move |t, r| t.id == thread2.id && *r == ExitReason::user(exit_code))
            .returning(|_, _| false);

        let policy = SystemCalls::new(&pa, &pm, &tm, &qm);

        let usm = MockActiveUserSpaceTables::new();

        let mut registers = Registers::default();
        registers.x[0] = exit_code as usize;

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::ExitCurrentThread.into_integer(),
                &thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::ScheduleNextThread)
        );
    }

    #[test]
    fn exit_thread_exits_process() {
        let pa = MockPageAllocator::new();
        let mut pm = MockProcessManager::new();
        let mut tm = MockThreadManager::new();
        let qm = MockQueueManager::new();

        let exit_code = 7;

        let proc = crate::process::tests::create_test_process(
            ProcessId::new(7).unwrap(),
            crate::process::Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(8).unwrap(),
        )
        .unwrap();

        let thread = Arc::new(Thread::new(
            ThreadId::new(9).unwrap(),
            Some(proc.clone()),
            State::Running,
            ProcessorState::new_for_user_thread(VirtualAddress::null(), VirtualAddress::null(), 0),
            (VirtualAddress::null(), 0),
        ));

        let thread2 = thread.clone();
        tm.expect_exit_thread()
            .once()
            .withf(move |t, r| t.id == thread2.id && *r == ExitReason::user(exit_code))
            .returning(|_, _| true);

        pm.expect_kill_process()
            .once()
            .withf(move |p, r| p.id == proc.id && *r == ExitReason::user(exit_code))
            .returning(|_, _| ());

        let policy = SystemCalls::new(&pa, &pm, &tm, &qm);

        let usm = MockActiveUserSpaceTables::new();

        let mut registers = Registers::default();
        registers.x[0] = exit_code as usize;

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::ExitCurrentThread.into_integer(),
                &thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::ScheduleNextThread)
        );
    }
}
