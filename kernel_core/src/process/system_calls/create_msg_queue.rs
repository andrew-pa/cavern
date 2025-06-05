use alloc::sync::Arc;

use kernel_api::QueueId;
use snafu::ResultExt;

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        PageAllocator,
    },
    process::{
        queue::QueueManager,
        thread::{Registers, ThreadManager},
        ProcessManager, Thread,
    },
};

use super::{Error, InvalidAddressSnafu, ManagerSnafu, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    pub(super) fn syscall_create_msg_queue<AUST: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, AUST>,
    ) -> Result<(), Error> {
        let dst: &mut QueueId = user_space_memory
            .check_mut_ref(registers.x[0].into())
            .context(InvalidAddressSnafu {
                cause: "output pointer",
            })?;

        let q = self
            .queue_manager
            .create_queue(current_thread.parent.as_ref().unwrap())
            .context(ManagerSnafu)?;

        *dst = q.id;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use core::mem::MaybeUninit;
    use mockall::predicate::function;
    use std::assert_matches::assert_matches;

    use kernel_api::{CallNumber, ProcessId};

    use crate::{
        memory::active_user_space_tables::AlwaysValidActiveUserSpaceTables,
        process::{
            queue::{MessageQueue, MockQueueManager},
            system_calls::SysCallEffect,
            tests::PAGE_ALLOCATOR,
            thread::MockThreadManager,
            ManagerError, MockProcessManager, Process, Properties, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn create_message_queue_success() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(200).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(201).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        // Queue-manager mock: expect one queue creation for `proc`
        let mut qm = MockQueueManager::new();
        let new_qid = QueueId::new(0xdead).unwrap();
        qm.expect_create_queue()
            .with(function(move |owner: &Arc<Process>| {
                Arc::ptr_eq(owner, &proc)
            }))
            .return_once(move |owner| Ok(Arc::new(MessageQueue::new(new_qid.into(), &owner))));

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut out_qid = MaybeUninit::<QueueId>::uninit();
        let mut regs = Registers::default();
        regs.x[0] = &mut out_qid as *mut _ as usize;

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::CreateMessageQueue.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
        assert_eq!(unsafe { out_qid.assume_init() }, new_qid);
    }
    #[test]
    fn create_message_queue_bad_ptr() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(202).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(203).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = 0; // null pointer ⇒ invalid

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::CreateMessageQueue.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::InvalidAddress { .. })
        );
    }
    #[test]
    fn create_message_queue_out_of_handles() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(318).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(319).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        // Queue-manager mock: no handles left.
        let mut qm = MockQueueManager::new();
        qm.expect_create_queue()
            .returning(|_| Err(ManagerError::OutOfHandles));

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut out_qid = MaybeUninit::<QueueId>::uninit();
        let mut regs = Registers::default();
        regs.x[0] = &mut out_qid as *mut _ as usize;

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::CreateMessageQueue.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::Manager {
                source: ManagerError::OutOfHandles
            })
        );
    }
}
