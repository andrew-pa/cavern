use alloc::{format, sync::Arc};

use log::debug;
use snafu::ResultExt;

use crate::{
    memory::{PageAllocator, VirtualAddress},
    process::{
        queue::QueueManager,
        system_calls::ManagerSnafu,
        thread::{Registers, ThreadManager},
        Process, ProcessManager,
    },
};

use super::{Error, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    pub(super) fn syscall_free_heap_pages(
        &self,
        current_process: &Arc<Process>,
        registers: &Registers,
    ) -> Result<(), Error> {
        let ptr: VirtualAddress = registers.x[0].into();
        let size: usize = registers.x[1];
        debug!(
            "freeing {size} pages @ {ptr:?} for process #{}",
            current_process.id
        );
        current_process
            .free_memory(self.page_allocator, ptr, size)
            .with_context(|_| ManagerSnafu {
                reason: format!(
                    "freeing {size} pages at {ptr:?} for process #{}",
                    current_process.id
                ),
            })
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
            thread::MockThreadManager, ManagerError, MemoryProperties, MockProcessManager,
            Properties, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn normal_free_heap_pages() {
        let pa = &*PAGE_ALLOCATOR;
        let parent_proc = crate::process::tests::create_test_process(
            ProcessId::new(60).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(61).unwrap(),
        )
        .unwrap();

        let mem = parent_proc
            .allocate_memory(
                pa,
                1,
                MemoryProperties {
                    owned: true,
                    user_space_access: true,
                    writable: true,
                    ..Default::default()
                },
            )
            .expect("allocate");

        let current_thread = parent_proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut registers = Registers::default();
        registers.x[0] = mem.into();
        registers.x[1] = 1;

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::FreeHeapPages.into_integer(),
                &current_thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
    }
    #[test]
    fn free_heap_pages_zero_size_invalid_length() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(308).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(309).unwrap(),
        )
        .unwrap();
        // Allocate one page so we have something to (incorrectly) free.
        let ptr = proc
            .allocate_memory(
                pa,
                1,
                MemoryProperties {
                    owned: true,
                    user_space_access: true,
                    writable: true,
                    ..Default::default()
                },
            )
            .unwrap();

        let current_thread = proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = usize::from(ptr); // valid pointer
        regs.x[1] = 0; // size = 0 ⇒ invalid

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::FreeHeapPages.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::Manager {
                source: ManagerError::PageTables { .. },
                reason: _,
            })
        );
    }
}
