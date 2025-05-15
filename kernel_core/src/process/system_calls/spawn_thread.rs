use alloc::sync::Arc;

use kernel_api::ThreadCreateInfo;
use log::debug;
use snafu::{ensure, ResultExt};

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        PageAllocator, VirtualAddress,
    },
    process::{
        queue::QueueManager,
        thread::{Registers, ThreadManager},
        Process, ProcessManager,
    },
};

use super::{
    Error, InvalidAddressSnafu, InvalidLengthSnafu, InvalidPointerSnafu, ManagerSnafu, SystemCalls,
};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    pub(super) fn syscall_spawn_thread<T: ActiveUserSpaceTables>(
        &self,
        parent: Arc<Process>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, T>,
    ) -> Result<(), Error> {
        let info: &ThreadCreateInfo =
            user_space_memory
                .check_ref(registers.x[0].into())
                .context(InvalidAddressSnafu {
                    cause: "thread info",
                })?;
        let out_thread_id = user_space_memory
            .check_mut_ref(registers.x[1].into())
            .context(InvalidAddressSnafu {
                cause: "output thread id",
            })?;

        let entry_ptr = VirtualAddress::from(info.entry as *mut ());
        ensure!(
            !entry_ptr.is_null(),
            InvalidPointerSnafu {
                reason: "thread entry point ptr",
                ptr: entry_ptr
            }
        );
        ensure!(
            info.stack_size > 0,
            InvalidLengthSnafu {
                reason: "stack size <= 0",
                length: info.stack_size
            }
        );

        let notify_on_exit = info
            .notify_on_exit
            .map(|q| self.queue_by_id_checked(q, &parent))
            .transpose()?;

        debug!("spawning thread {info:?} in process #{}", parent.id);

        let thread = self
            .thread_manager
            .spawn_thread(parent, entry_ptr, info.stack_size, info.user_data)
            .context(ManagerSnafu)?;

        // if provided a queue, subscribe it to the thread exit
        if let Some(qu) = notify_on_exit {
            thread.exit_subscribers.lock().push(qu);
        }

        *out_thread_id = thread.id;

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
        memory::{active_user_space_tables::AlwaysValidActiveUserSpaceTables, VirtualAddress},
        process::{
            queue::{MessageQueue, MockQueueManager},
            system_calls::SysCallEffect,
            tests::PAGE_ALLOCATOR,
            thread::{MockThreadManager, ProcessorState, State},
            MockProcessManager, QueueId, Thread, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn normal_spawn_thread() {
        fn test_entry(_: usize) -> ! {
            unreachable!()
        }

        let pm = MockProcessManager::new();
        let mut tm = MockThreadManager::new();
        let qm = MockQueueManager::new();

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

        let new_thread = Arc::new(Thread::new(
            ThreadId::new(9).unwrap(),
            Some(proc.clone()),
            State::Running,
            ProcessorState::new_for_user_thread(VirtualAddress::null(), VirtualAddress::null(), 0),
            (VirtualAddress::null(), 0),
        ));

        let info = ThreadCreateInfo {
            entry: test_entry,
            stack_size: 100,
            user_data: 777,
            notify_on_exit: None,
        };
        let info_ptr = &raw const info;

        let mut thread_id = 0;
        let thread_id_ptr = &raw mut thread_id;

        let pid = proc.id;
        tm.expect_spawn_thread()
            .with(
                mockall::predicate::function(move |p: &Arc<Process>| p.id == pid),
                eq(VirtualAddress::from(test_entry as usize)),
                eq(info.stack_size),
                eq(info.user_data),
            )
            .return_once(|_, _, _, _| Ok(new_thread));

        let mut registers = Registers::default();
        registers.x[0] = info_ptr as _;
        registers.x[1] = thread_id_ptr as _;

        let th = proc.threads.read().first().unwrap().clone();

        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::SpawnThread.into_integer(),
                &th,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );

        assert_eq!(thread_id, 9);
    }

    #[test]
    fn spawn_thread_and_subscribe_to_exit() {
        fn test_entry(_: usize) -> ! {
            unreachable!()
        }

        let pm = MockProcessManager::new();
        let mut tm = MockThreadManager::new();
        let mut qm = MockQueueManager::new();

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

        let qid = QueueId::new(15).unwrap();
        let qu = Arc::new(MessageQueue::new(qid, &proc));
        qm.expect_queue_for_id()
            .with(eq(qid))
            .return_once(|_| Some(qu));

        let new_thread = Arc::new(Thread::new(
            ThreadId::new(9).unwrap(),
            Some(proc.clone()),
            State::Running,
            ProcessorState::new_for_user_thread(VirtualAddress::null(), VirtualAddress::null(), 0),
            (VirtualAddress::null(), 0),
        ));
        let new_thread2 = new_thread.clone();

        let info = ThreadCreateInfo {
            entry: test_entry,
            stack_size: 100,
            user_data: 777,
            notify_on_exit: Some(qid),
        };
        let info_ptr = &raw const info;

        let mut thread_id = 0;
        let thread_id_ptr = &raw mut thread_id;

        let pid = proc.id;
        tm.expect_spawn_thread()
            .with(
                mockall::predicate::function(move |p: &Arc<Process>| p.id == pid),
                eq(VirtualAddress::from(test_entry as usize)),
                eq(info.stack_size),
                eq(info.user_data),
            )
            .return_once(|_, _, _, _| Ok(new_thread));

        let mut registers = Registers::default();
        registers.x[0] = info_ptr as _;
        registers.x[1] = thread_id_ptr as _;

        let th = proc.threads.read().first().unwrap().clone();

        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::SpawnThread.into_integer(),
                &th,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );

        assert_eq!(thread_id, 9);
        assert!(new_thread2
            .exit_subscribers
            .lock()
            .iter()
            .any(|q| q.id == qid));
    }
}
