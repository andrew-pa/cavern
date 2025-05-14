use alloc::sync::Arc;

use log::debug;
use snafu::ResultExt;

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        page_table::MemoryProperties,
        PageAllocator,
    },
    process::{
        queue::QueueManager,
        system_calls::{InvalidAddressSnafu, ManagerSnafu},
        thread::{Registers, ThreadManager},
        Process, ProcessManager,
    },
};

use super::{Error, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    pub(super) fn syscall_allocate_heap_pages<T: ActiveUserSpaceTables>(
        &self,
        current_process: &Arc<Process>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, T>,
    ) -> Result<(), Error> {
        let size: usize = registers.x[0];
        let dst: &mut usize = user_space_memory
            .check_mut_ref(registers.x[1].into())
            .context(InvalidAddressSnafu {
                cause: "output pointer",
            })?;

        debug!(
            "allocating {size} pages for process #{}",
            current_process.id
        );

        let addr = current_process
            .allocate_memory(
                self.page_allocator,
                size,
                MemoryProperties {
                    user_space_access: true,
                    writable: true,
                    executable: true,
                    ..Default::default()
                },
            )
            .context(ManagerSnafu)?;

        *dst = addr.into();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use std::assert_matches::assert_matches;

    use kernel_api::{CallNumber, ProcessId};

    use crate::{
        memory::active_user_space_tables::AlwaysValidActiveUserSpaceTables,
        process::{
            queue::MockQueueManager, system_calls::SysCallEffect, tests::PAGE_ALLOCATOR,
            thread::MockThreadManager, MockProcessManager, Properties, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn normal_allocate_heap_pages() {
        let pa = &*PAGE_ALLOCATOR;
        let parent_proc = crate::process::tests::create_test_process(
            ProcessId::new(50).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(51).unwrap(),
        )
        .unwrap();

        let current_thread = parent_proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let pages = 3;
        let mut alloc_result: usize = 0;
        let alloc_result_ptr = &mut alloc_result as *mut usize;

        let mut registers = Registers::default();
        registers.x[0] = pages;
        registers.x[1] = alloc_result_ptr as usize;

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::AllocateHeapPages.into_integer(),
                &current_thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
        assert_ne!(alloc_result, 0);
    }
    #[test]
    fn allocate_heap_pages_zero_size_invalid_length() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(306).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(307).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = 0; // size = 0 ⇒ invalid

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::AllocateHeapPages.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::InvalidAddress { .. })
        );
    }
}
