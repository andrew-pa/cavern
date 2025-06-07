use alloc::{sync::Arc, vec::Vec};

use log::debug;
use snafu::{ensure, ResultExt};

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        PageAllocator,
    },
    process::{
        queue::QueueManager, system_calls::InvalidHandleSnafu, thread::{Registers, ThreadManager}, Process, ProcessManager
    },
};

use super::{Error, InvalidAddressSnafu, ManagerSnafu, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    pub(super) fn syscall_spawn_process<T: ActiveUserSpaceTables>(
        &self,
        parent: Arc<Process>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, T>,
    ) -> Result<(), Error> {
        let uinfo: &kernel_api::ProcessCreateInfo = user_space_memory
            .check_ref(registers.x[0].into())
            .context(InvalidAddressSnafu {
                cause: "process info",
            })?;

        let out_process_id = user_space_memory
            .check_mut_ref(registers.x[1].into())
            .context(InvalidAddressSnafu {
                cause: "output process id",
            })?;

        let out_queue_id = if registers.x[2] > 0 {
            Some(
                user_space_memory
                    .check_mut_ref(registers.x[2].into())
                    .context(InvalidAddressSnafu {
                        cause: "output queue id",
                    })?,
            )
        } else {
            None
        };

        let notify_on_exit = uinfo
            .notify_on_exit
            .map(|q| self.queue_by_id_checked(q, &parent))
            .transpose()?;

        let user_sections = user_space_memory
            .check_slice(uinfo.sections.into(), uinfo.num_sections)
            .context(InvalidAddressSnafu {
                cause: "process image sections slice",
            })?;

        // check each section's data slice
        let sections = user_sections
            .iter()
            .map(|s| {
                Ok(crate::process::ImageSection {
                    base_address: s.base_address.into(),
                    data_offset: s.data_offset,
                    total_size: s.total_size,
                    data: user_space_memory
                        .check_slice(s.data.into(), s.data_size)
                        .context(InvalidAddressSnafu {
                            cause: "process image section data slice",
                        })?,
                    kind: s.kind,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        ensure!(uinfo.supervisor.is_some() || parent.props.supervisor_queue.is_some(), 
            InvalidHandleSnafu {
                reason: "Root process must provide supervisor queue for child processes", handle: 0u32
        });

        let info = crate::process::ProcessCreateInfo {
            sections: &sections,
            supervisor: uinfo.supervisor,
            registry: uinfo.registry,
            privilege_level: uinfo.privilege_level,
            inbox_size: uinfo.inbox_size,
        };

        debug!("spawning process {info:?}, parent #{}", parent.id);
        let proc = self
            .process_manager
            .spawn_process(Some(parent), &info)
            .context(ManagerSnafu)?;

        // if the user requested an exit subscription, add it
        if let Some(q) = notify_on_exit {
            proc.exit_subscribers.lock().push(q);
        }

        // create the initial queue
        let qu = self
            .queue_manager
            .create_queue(&proc)
            .context(ManagerSnafu)?;

        // spawn the main thread with an 8 MiB stack
        self.thread_manager
            .spawn_thread(
                proc.clone(),
                uinfo.entry_point.into(),
                8 * 1024 * 1024 / self.page_allocator.page_size(),
                qu.id.get() as usize,
            )
            .context(ManagerSnafu)?;

        debug!("process #{} spawned (main queue #{})", proc.id, qu.id);

        *out_process_id = proc.id;
        if let Some(oqi) = out_queue_id {
            *oqi = qu.id;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use std::assert_matches::assert_matches;

    use kernel_api::{CallNumber, ProcessId};
    use mockall::predicate::{eq, function};

    use crate::{
        memory::{active_user_space_tables::AlwaysValidActiveUserSpaceTables, VirtualAddress},
        process::{
            queue::{MessageQueue, MockQueueManager},
            system_calls::SysCallEffect,
            tests::PAGE_ALLOCATOR,
            thread::{MockThreadManager, ProcessorState, State},
            MockProcessManager, Properties, QueueId, Thread, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn normal_spawn_process() {
        let mut pm = MockProcessManager::new();
        let mut tm = MockThreadManager::new();
        let mut qm = MockQueueManager::new();
        let parent_proc = crate::process::tests::create_test_process(
            ProcessId::new(10).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(11).unwrap(),
        )
        .unwrap();

        let dummy_info = kernel_api::ProcessCreateInfo {
            entry_point: 0,
            num_sections: 0,
            sections: core::ptr::null(),
            supervisor: None,
            registry: None,
            privilege_level: kernel_api::PrivilegeLevel::Unprivileged,
            notify_on_exit: None,
            inbox_size: 0,
        };
        let info_ptr = &dummy_info as *const _;
        let mut process_id: u32 = 0;
        let process_id_ptr = &mut process_id as *mut u32;
        let mut queue_id: u32 = 0;
        let queue_id_ptr = &mut queue_id as *mut u32;

        let parent_thread = parent_proc.threads.read().first().unwrap().clone();
        // Create a new process that will be returned by spawn_process.
        let new_proc_id = ProcessId::new(20).unwrap();
        let new_proc = crate::process::tests::create_test_process(
            new_proc_id,
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(21).unwrap(),
        )
        .unwrap();

        // Expect spawn_process to be called with the proper parent.
        let parent_clone = parent_proc.clone();
        let new_proc2 = new_proc.clone();
        pm.expect_spawn_process()
            .withf(move |p, _| p.as_ref().is_some_and(|p| p.id == parent_clone.id))
            .return_once(move |_, _| Ok(new_proc2));

        let new_queue_id = QueueId::new(34).unwrap();
        qm.expect_create_queue()
            .withf(move |o| o.id == new_proc_id)
            .return_once(move |o| Ok(Arc::new(MessageQueue::new(new_queue_id, o))));

        let new_thread_id = ThreadId::new(234).unwrap();
        tm.expect_spawn_thread()
            .with(
                function(move |p: &Arc<Process>| p.id == new_proc_id),
                eq(VirtualAddress::from(dummy_info.entry_point)),
                eq(2048),
                eq(new_queue_id.get() as usize),
            )
            .return_once(move |p, entry, stack_size, user_data| {
                Ok(Arc::new(Thread::new(
                    new_thread_id,
                    Some(p),
                    State::Running,
                    ProcessorState::new_for_user_thread(entry, VirtualAddress::null(), user_data),
                    (VirtualAddress::null(), stack_size),
                )))
            });

        let pa = &*PAGE_ALLOCATOR;
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut registers = Registers::default();
        registers.x[0] = info_ptr as usize;
        registers.x[1] = process_id_ptr as usize;
        registers.x[2] = queue_id_ptr as usize;

        // The current thread (from parent_proc) is used so that its parent is set.
        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::SpawnProcess.into_integer(),
                &parent_thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
        assert_eq!(process_id, new_proc_id.get());
        assert_eq!(queue_id, new_queue_id.get());
    }

    #[test]
    fn spawn_process_and_subscribe_to_exit() {
        let mut pm = MockProcessManager::new();
        let mut tm = MockThreadManager::new();
        let mut qm = MockQueueManager::new();
        let parent_proc = crate::process::tests::create_test_process(
            ProcessId::new(10).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(11).unwrap(),
        )
        .unwrap();

        let qid = QueueId::new(15).unwrap();
        let qu = Arc::new(MessageQueue::new(qid, &parent_proc));
        qm.expect_queue_for_id()
            .with(eq(qid))
            .return_once(|_| Some(qu));

        let dummy_info = kernel_api::ProcessCreateInfo {
            entry_point: 0,
            num_sections: 0,
            sections: core::ptr::null(),
            supervisor: None,
            registry: None,
            privilege_level: kernel_api::PrivilegeLevel::Unprivileged,
            notify_on_exit: Some(qid),
            inbox_size: 0,
        };
        let info_ptr = &dummy_info as *const _;
        let mut process_id: u32 = 0;
        let process_id_ptr = &mut process_id as *mut u32;
        let mut queue_id: u32 = 0;
        let queue_id_ptr = &mut queue_id as *mut u32;

        let parent_thread = parent_proc.threads.read().first().unwrap().clone();
        // Create a new process that will be returned by spawn_process.
        let new_proc_id = ProcessId::new(20).unwrap();
        let new_proc = crate::process::tests::create_test_process(
            new_proc_id,
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(21).unwrap(),
        )
        .unwrap();

        // Expect spawn_process to be called with the proper parent.
        let parent_clone = parent_proc.clone();
        let new_proc2 = new_proc.clone();
        pm.expect_spawn_process()
            .withf(move |p, _| p.as_ref().is_some_and(|p| p.id == parent_clone.id))
            .return_once(move |_, _| Ok(new_proc2));

        let new_queue_id = QueueId::new(34).unwrap();
        qm.expect_create_queue()
            .withf(move |o| o.id == new_proc_id)
            .return_once(move |o| Ok(Arc::new(MessageQueue::new(new_queue_id, o))));

        let new_thread_id = ThreadId::new(234).unwrap();
        tm.expect_spawn_thread()
            .with(
                function(move |p: &Arc<Process>| p.id == new_proc_id),
                eq(VirtualAddress::from(dummy_info.entry_point)),
                eq(2048),
                eq(new_queue_id.get() as usize),
            )
            .return_once(move |p, entry, stack_size, user_data| {
                Ok(Arc::new(Thread::new(
                    new_thread_id,
                    Some(p),
                    State::Running,
                    ProcessorState::new_for_user_thread(entry, VirtualAddress::null(), user_data),
                    (VirtualAddress::null(), stack_size),
                )))
            });

        let pa = &*PAGE_ALLOCATOR;
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut registers = Registers::default();
        registers.x[0] = info_ptr as usize;
        registers.x[1] = process_id_ptr as usize;
        registers.x[2] = queue_id_ptr as usize;

        // The current thread (from parent_proc) is used so that its parent is set.
        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::SpawnProcess.into_integer(),
                &parent_thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
        assert_eq!(process_id, new_proc_id.get());
        assert_eq!(queue_id, new_queue_id.get());
        assert!(new_proc.exit_subscribers.lock().iter().any(|q| q.id == qid));
    }

    #[test]
    fn spawn_process_invalid_info_ptr() {
        let pa = &*PAGE_ALLOCATOR;
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let parent_proc = crate::process::tests::create_test_process(
            ProcessId::new(100).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(101).unwrap(),
        )
        .unwrap();
        let parent_thread = parent_proc.threads.read().first().unwrap().clone();

        let mut registers = Registers::default();
        registers.x[0] = 0; // null pointer for ProcessCreateInfo
        registers.x[1] = 0;
        registers.x[2] = 0;

        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());
        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::SpawnProcess.into_integer(),
                &parent_thread,
                &registers,
                &usm
            ),
            Err(Error::InvalidAddress { .. })
        );
    }
}
