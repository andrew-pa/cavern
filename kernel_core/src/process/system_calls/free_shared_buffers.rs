use alloc::{format, sync::Arc};

use kernel_api::SharedBufferId;
use snafu::ResultExt;

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        PageAllocator,
    },
    process::{
        queue::QueueManager,
        system_calls::{InvalidAddressSnafu, ManagerSnafu},
        thread::{Registers, ThreadManager},
        ProcessManager, Thread,
    },
};

use super::{Error, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    #[allow(clippy::unused_self)]
    pub(super) fn syscall_free_shared_buffers<AUST: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, AUST>,
    ) -> Result<(), Error> {
        let buffers: &[SharedBufferId] = user_space_memory
            .check_slice(registers.x[0].into(), registers.x[1])
            .context(InvalidAddressSnafu {
                cause: "buffers slice",
            })?;

        let proc = current_thread.parent.as_ref().unwrap();

        proc.free_shared_buffers(buffers.iter().copied())
            .with_context(|_| ManagerSnafu {
                reason: format!("freeing shared buffers for process #{}", proc.id),
            })
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use core::num::NonZeroU32;
    use std::assert_matches::assert_matches;

    use kernel_api::{flags::SharedBufferFlags, CallNumber, ProcessId};

    use crate::{
        memory::{active_user_space_tables::AlwaysValidActiveUserSpaceTables, VirtualAddress},
        process::{
            queue::MockQueueManager, system_calls::SysCallEffect, tests::PAGE_ALLOCATOR,
            thread::MockThreadManager, ManagerError, MockProcessManager, Properties, SharedBuffer,
            ThreadId,
        },
    };

    use super::*;
    #[test]
    fn normal_free_shared_buffers() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(110).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(111).unwrap(),
        )
        .unwrap();

        let buf = proc
            .shared_buffers
            .insert(Arc::new(SharedBuffer {
                owner: proc.clone(),
                flags: SharedBufferFlags::empty(),
                base_address: VirtualAddress::null(),
                length: 0,
            }))
            .unwrap();

        let current_thread = proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let buffer_ids = [buf];
        let mut registers = Registers::default();
        registers.x[0] = buffer_ids.as_ptr() as usize;
        registers.x[1] = buffer_ids.len();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::FreeSharedBuffers.into_integer(),
                &current_thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );

        assert!(proc.shared_buffers.get(buf).is_none());
    }
    #[test]
    fn free_shared_buffers_not_found() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(316).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(317).unwrap(),
        )
        .unwrap();
        // Insert exactly one valid handle.
        let valid = proc
            .shared_buffers
            .insert(Arc::new(SharedBuffer {
                owner: proc.clone(),
                flags: SharedBufferFlags::empty(),
                base_address: VirtualAddress::null(),
                length: 0,
            }))
            .unwrap();
        // Unknown handle (never allocated).
        let unknown = NonZeroU32::new(0xaaaa).unwrap();
        let buffers = [valid, unknown];

        let current_thread = proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = buffers.as_ptr() as usize;
        regs.x[1] = buffers.len();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::FreeSharedBuffers.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::Manager {
                source: ManagerError::Missing { .. },
                reason: _,
            })
        );
    }
}
