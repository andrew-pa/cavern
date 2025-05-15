use alloc::sync::Arc;
use bytemuck::Contiguous;
use kernel_api::EnvironmentValue;
use log::trace;

use crate::{
    memory::PageAllocator,
    process::{
        queue::QueueManager,
        thread::{Registers, ThreadManager},
        ProcessManager, Thread,
    },
};

use super::SystemCalls;

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    pub(super) fn syscall_read_env_value(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
    ) -> usize {
        let Some(value_to_read) = EnvironmentValue::from_integer(registers.x[0]) else {
            return 0;
        };
        trace!(
            "reading value {value_to_read:?} for thread {}",
            current_thread.id
        );
        let current_proc = current_thread
            .parent
            .as_ref()
            .expect("kernel threads don't make syscalls");
        match value_to_read {
            EnvironmentValue::CurrentProcessId => current_proc.id.get() as usize,
            EnvironmentValue::CurrentThreadId => current_thread.id.get() as usize,
            EnvironmentValue::CurrentSupervisorQueueId => current_proc
                .props
                .supervisor_queue
                .map_or(0, |id| id.get() as usize),
            EnvironmentValue::CurrentRegistryQueueId => current_proc
                .props
                .registry_queue
                .map_or(0, |id| id.get() as usize),
            EnvironmentValue::PageSizeInBytes => self.page_allocator.page_size().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches::assert_matches;

    use kernel_api::{CallNumber, ProcessId};

    use crate::{
        memory::active_user_space_tables::AlwaysValidActiveUserSpaceTables,
        process::{
            queue::MockQueueManager, system_calls::SysCallEffect, tests::PAGE_ALLOCATOR,
            thread::MockThreadManager, MockProcessManager, Properties, QueueId, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn read_env_value_page_size() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(320).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(321).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = EnvironmentValue::PageSizeInBytes.into_integer();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::ReadEnvValue.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(size)) if size == pa.page_size().into()
        );
    }

    #[test]
    fn read_process_id() {
        let pa = &*PAGE_ALLOCATOR;
        let pid = ProcessId::new(320).unwrap();
        let proc = crate::process::tests::create_test_process(
            pid,
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(321).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = EnvironmentValue::CurrentProcessId.into_integer();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::ReadEnvValue.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(v)) if v as u32 == pid.get()
        );
    }

    #[test]
    fn read_supervisor_queue_id() {
        let pa = &*PAGE_ALLOCATOR;
        let pid = ProcessId::new(320).unwrap();
        let qid = QueueId::new(789).unwrap();
        let proc = crate::process::tests::create_test_process(
            pid,
            Properties {
                supervisor_queue: Some(qid),
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(321).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = EnvironmentValue::CurrentSupervisorQueueId.into_integer();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::ReadEnvValue.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(v)) if v as u32 == qid.get()
        );
    }

    #[test]
    fn read_registry_queue_id() {
        let pa = &*PAGE_ALLOCATOR;
        let pid = ProcessId::new(320).unwrap();
        let qid = QueueId::new(789).unwrap();
        let proc = crate::process::tests::create_test_process(
            pid,
            Properties {
                supervisor_queue: None,
                registry_queue: Some(qid),
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(321).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = EnvironmentValue::CurrentRegistryQueueId.into_integer();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::ReadEnvValue.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(v)) if v as u32 == qid.get()
        );
    }

    #[test]
    fn read_current_thread_id() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(320).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(321).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = EnvironmentValue::CurrentThreadId.into_integer();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::ReadEnvValue.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(v)) if v as u32 == current_thread.id.get()
        );
    }
}
