use kernel_api::QueueId;
use log::debug;
use snafu::OptionExt;

use crate::{
    memory::PageAllocator,
    process::{
        queue::QueueManager,
        system_calls::{InvalidHandleSnafu, NotFoundSnafu},
        thread::{Registers, ThreadManager},
        ProcessManager,
    },
};

use super::{Error, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    pub(super) fn syscall_free_msg_queue(&self, registers: &Registers) -> Result<(), Error> {
        let queue_id = QueueId::new(registers.x[0] as _).context(InvalidHandleSnafu {
            reason: "queue id zero",
            handle: 0u32,
        })?;
        let qu = self
            .queue_manager
            .queue_for_id(queue_id)
            .context(NotFoundSnafu {
                reason: "queue id",
                id: queue_id.get() as usize,
            })?;
        debug!("freeing message queue #{}", qu.id);
        self.queue_manager.free_queue(&qu);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use mockall::predicate::{eq, function};
    use std::{assert_matches::assert_matches, sync::Arc};

    use kernel_api::{CallNumber, ProcessId};

    use crate::{
        memory::active_user_space_tables::AlwaysValidActiveUserSpaceTables,
        process::{
            queue::{MessageQueue, MockQueueManager},
            system_calls::SysCallEffect,
            tests::PAGE_ALLOCATOR,
            thread::MockThreadManager,
            MockProcessManager, Properties, ThreadId,
        },
    };

    use super::*;
    #[test]
    fn free_message_queue_success() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(210).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(211).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        // Pre-create a queue that will be freed
        let qid = QueueId::new(0xbeef).unwrap();
        let queue = Arc::new(MessageQueue::new(qid.into(), &proc));

        let mut qm = MockQueueManager::new();
        let queue2 = queue.clone();
        qm.expect_queue_for_id()
            .with(eq(qid))
            .return_once(move |_| Some(queue2));
        qm.expect_free_queue()
            .with(function(move |q: &Arc<MessageQueue>| {
                Arc::ptr_eq(q, &queue)
            }))
            .return_once(|_| ());

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = qid.get() as usize;

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::FreeMessageQueue.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
    }
    #[test]
    fn free_message_queue_not_found() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(212).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(213).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let mut qm = MockQueueManager::new();
        qm.expect_queue_for_id().return_const(None);

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = 0x9999; // unknown id

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::FreeMessageQueue.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::NotFound { .. })
        );
    }
}
