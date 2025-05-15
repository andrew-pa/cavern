use alloc::sync::Arc;

use kernel_api::{flags::ExitNotificationSubscriptionFlags, ProcessId, QueueId, ThreadId};
use log::debug;
use snafu::{ensure, OptionExt};

use crate::{
    memory::PageAllocator,
    process::{
        queue::QueueManager,
        system_calls::{InvalidFlagsSnafu, InvalidHandleSnafu, NotFoundSnafu, NotPermittedSnafu},
        thread::{Registers, ThreadManager},
        MessageQueue, ProcessManager, Thread,
    },
};

use super::{Error, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    pub(super) fn syscall_exit_notification_subscription(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
    ) -> Result<(), Error> {
        let flags = ExitNotificationSubscriptionFlags::from_bits(registers.x[0]).context(
            InvalidFlagsSnafu {
                reason: "invalid flag bits",
                bits: registers.x[0],
            },
        )?;

        ensure!(
            !flags.contains(
                ExitNotificationSubscriptionFlags::PROCESS
                    | ExitNotificationSubscriptionFlags::THREAD
            ) && !flags.is_empty(),
            InvalidFlagsSnafu {
                reason: "process mode xor thread mode",
                bits: registers.x[0]
            }
        );

        let receiver_queue = QueueId::new(registers.x[2] as u32)
            .context(InvalidHandleSnafu {
                reason: "queue id is zero",
                handle: 0u32,
            })
            .and_then(|qid| {
                self.queue_manager.queue_for_id(qid).context(NotFoundSnafu {
                    reason: "queue id not found",
                    id: qid.get() as usize,
                })
            })?;

        ensure!(
            receiver_queue
                .owner
                .upgrade()
                .is_some_and(|q| q.id == current_thread.parent.as_ref().unwrap().id),
            NotPermittedSnafu {
                reason: "must own queue to (un)subscribe it to exit notifications"
            }
        );

        let process_subscription = |exit_subs: &mut alloc::vec::Vec<_>| {
            if flags.contains(ExitNotificationSubscriptionFlags::UNSUBSCRIBE) {
                exit_subs.retain_mut(|q: &mut Arc<MessageQueue>| q.id != receiver_queue.id);
            } else if !exit_subs.iter().any(|q| q.id == receiver_queue.id) {
                exit_subs.push(receiver_queue.clone());
            }
        };

        if flags.contains(ExitNotificationSubscriptionFlags::PROCESS) {
            let proc = ProcessId::new(registers.x[1] as u32)
                .and_then(|id| self.process_manager.process_for_id(id))
                .context(InvalidHandleSnafu {
                    reason: "process id unknown",
                    handle: registers.x[1] as u32,
                })?;
            debug!(
                "subscribing queue #{} to exit of process #{}",
                receiver_queue.id, proc.id
            );
            let mut s = proc.exit_subscribers.lock();
            process_subscription(&mut s);
        } else if flags.contains(ExitNotificationSubscriptionFlags::THREAD) {
            let thread = ThreadId::new(registers.x[1] as u32)
                .and_then(|id| self.thread_manager.thread_for_id(id))
                .context(InvalidHandleSnafu {
                    reason: "thread id unknown",
                    handle: registers.x[1] as u32,
                })?;
            debug!(
                "subscribing queue #{} to exit of thread #{}",
                receiver_queue.id, thread.id
            );
            let mut s = thread.exit_subscribers.lock();
            process_subscription(&mut s);
        } else {
            return Err(Error::InvalidFlags {
                reason: "did not specific process or thread".into(),
                bits: flags.bits(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use mockall::predicate::eq;
    use std::assert_matches::assert_matches;

    use kernel_api::{CallNumber, ProcessId};

    use crate::{
        memory::active_user_space_tables::AlwaysValidActiveUserSpaceTables,
        process::{
            queue::MockQueueManager,
            system_calls::{tests::fake_thread, SysCallEffect},
            tests::PAGE_ALLOCATOR,
            thread::MockThreadManager,
            MockProcessManager, Properties,
        },
    };

    use super::*;

    #[test]
    fn normal_exit_notification_subscription_process() {
        let current_proc = crate::process::tests::create_test_process(
            ProcessId::new(120).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(121).unwrap(),
        )
        .unwrap();

        let current_thread = current_proc.threads.read().first().unwrap().clone();

        let queue_id = QueueId::new(1234).unwrap();
        let queue = Arc::new(MessageQueue::new(queue_id, &current_proc));

        // Create a target process for exit subscription.
        let target_proc = crate::process::tests::create_test_process(
            ProcessId::new(130).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(131).unwrap(),
        )
        .unwrap();

        let mut pm = MockProcessManager::new();
        let tp2 = target_proc.clone();
        pm.expect_process_for_id()
            .with(eq(target_proc.id))
            .return_once(move |_| Some(tp2));

        let mut qm = MockQueueManager::new();
        qm.expect_queue_for_id()
            .with(eq(queue_id))
            .return_once(|_| Some(queue));

        let flags = ExitNotificationSubscriptionFlags::PROCESS;

        let mut registers = Registers::default();
        registers.x[0] = flags.bits();
        registers.x[1] = target_proc.id.get() as usize;
        registers.x[2] = queue_id.get() as usize;

        let tm = MockThreadManager::new();
        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::ExitNotificationSubscription.into_integer(),
                &current_thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
        let subs = target_proc.exit_subscribers.lock();
        assert!(subs.iter().any(|q| q.id == queue_id));
    }

    #[test]
    fn normal_exit_notification_subscription_thread() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(140).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(141).unwrap(),
        )
        .unwrap();

        // Create an extra thread in the process.
        let extra_thread = fake_thread();
        proc.threads.write().push(extra_thread.clone());

        let queue_id = QueueId::new(1234).unwrap();
        let queue = Arc::new(MessageQueue::new(queue_id, &proc));

        let current_thread = proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let ex = extra_thread.clone();
        let mut tm = MockThreadManager::new();
        tm.expect_thread_for_id()
            .with(eq(extra_thread.id))
            .return_once(|_| Some(ex));
        let mut qm = MockQueueManager::new();
        qm.expect_queue_for_id()
            .with(eq(queue_id))
            .return_once(|_| Some(queue));
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let flags = ExitNotificationSubscriptionFlags::THREAD;

        let mut registers = Registers::default();
        registers.x[0] = flags.bits();
        registers.x[1] = extra_thread.id.get() as usize;
        registers.x[2] = queue_id.get() as usize;

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::ExitNotificationSubscription.into_integer(),
                &current_thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
        let subs = extra_thread.exit_subscribers.lock();
        assert!(subs.iter().any(|q| q.id == queue_id));
    }

    #[test]
    fn exit_notification_unsubscribe() {
        let current_proc = crate::process::tests::create_test_process(
            ProcessId::new(240).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(241).unwrap(),
        )
        .unwrap();
        let current_thread = current_proc.threads.read().first().unwrap().clone();

        // Queue to remove
        let qid = QueueId::new(0xcafe).unwrap();
        let queue = Arc::new(MessageQueue::new(qid.into(), &current_proc));
        current_proc.exit_subscribers.lock().push(queue.clone());

        let mut qm = MockQueueManager::new();
        qm.expect_queue_for_id()
            .with(eq(qid))
            .return_once(|_| Some(queue));

        let pa = &*PAGE_ALLOCATOR;
        let mut pm = MockProcessManager::new();
        let cp2 = current_proc.clone();
        pm.expect_process_for_id()
            .with(eq(current_proc.id))
            .return_once(|_| Some(cp2));
        let tm = MockThreadManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = (ExitNotificationSubscriptionFlags::UNSUBSCRIBE
            | ExitNotificationSubscriptionFlags::PROCESS)
            .bits();
        regs.x[1] = current_proc.id.get() as usize;
        regs.x[2] = qid.get() as usize;

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::ExitNotificationSubscription.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
        assert!(current_proc.exit_subscribers.lock().is_empty());
    }

    #[test]
    fn exit_notification_invalid_flags() {
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(242).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(243).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pa = &*PAGE_ALLOCATOR;
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = (ExitNotificationSubscriptionFlags::PROCESS
            | ExitNotificationSubscriptionFlags::THREAD)
            .bits();
        regs.x[1] = 0;
        regs.x[2] = 0;

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::ExitNotificationSubscription.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::InvalidFlags { .. })
        );
    }
}
