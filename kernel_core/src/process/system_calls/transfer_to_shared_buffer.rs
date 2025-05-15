use alloc::sync::Arc;

use kernel_api::SharedBufferId;
use snafu::{OptionExt, ResultExt};

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        PageAllocator,
    },
    process::{
        queue::QueueManager,
        system_calls::InvalidAddressSnafu,
        thread::{Registers, ThreadManager},
        ProcessManager, Thread,
    },
};

use super::{Error, InvalidHandleSnafu, SystemCalls, TransferSnafu};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    #[allow(clippy::unused_self)]
    pub(super) fn syscall_transfer_to<AUST: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, AUST>,
    ) -> Result<(), Error> {
        let proc = current_thread.parent.as_ref().unwrap();
        let buffer_handle =
            SharedBufferId::new(registers.x[0] as u32).context(InvalidHandleSnafu {
                reason: "buffer handle is zero",
                handle: 0u32,
            })?;
        let buf = proc
            .shared_buffers
            .get(buffer_handle)
            .context(InvalidHandleSnafu {
                reason: "buffer handle not found",
                handle: buffer_handle.get(),
            })?;
        let offset = registers.x[1];
        let src = user_space_memory
            .check_slice(registers.x[2].into(), registers.x[3])
            .context(InvalidAddressSnafu {
                cause: "source buffer",
            })?;
        buf.transfer_to(offset, src).context(TransferSnafu)
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use std::assert_matches::assert_matches;

    use kernel_api::{flags::SharedBufferFlags, CallNumber, ProcessId};

    use crate::{
        memory::{
            active_user_space_tables::AlwaysValidActiveUserSpaceTables,
            page_table::MemoryProperties,
        },
        process::{
            queue::MockQueueManager, system_calls::SysCallEffect, tests::PAGE_ALLOCATOR,
            thread::MockThreadManager, MockProcessManager, Properties, SharedBuffer, ThreadId,
            TransferError,
        },
    };

    use super::*;

    #[test]
    fn normal_transfer_to_shared_buffer() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(70).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(71).unwrap(),
        )
        .unwrap();

        let mem = proc
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

        // Insert a shared buffer into the process.
        let buffer = Arc::new(crate::process::SharedBuffer {
            owner: proc.clone(),
            flags: kernel_api::flags::SharedBufferFlags::WRITE,
            base_address: mem,
            length: 1024,
        });
        let handle = proc.shared_buffers.insert(buffer).unwrap();

        let current_thread = proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let src_data = [1u8, 2, 3, 4];
        let mut registers = Registers::default();
        registers.x[0] = handle.get() as usize;
        registers.x[1] = 0; // offset
        registers.x[2] = src_data.as_ptr() as usize;
        registers.x[3] = src_data.len();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::TransferToSharedBuffer.into_integer(),
                &current_thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
    }

    #[test]
    fn transfer_to_shared_buffer_out_of_bounds() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(250).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(251).unwrap(),
        )
        .unwrap();
        let mem = proc
            .allocate_memory(
                pa,
                1,
                MemoryProperties {
                    owned: true,
                    user_space_access: true,
                    writable: true,
                    ..MemoryProperties::default()
                },
            )
            .expect("alloc");
        let buf = Arc::new(SharedBuffer {
            owner: proc.clone(),
            flags: SharedBufferFlags::WRITE,
            base_address: mem,
            length: 32,
        });
        let handle = proc.shared_buffers.insert(buf).unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let data = [0u8; 32];
        let mut regs = Registers::default();
        regs.x[0] = handle.get() as usize;
        regs.x[1] = 16; // offset
        regs.x[2] = data.as_ptr() as usize; // copy 32 bytes
        regs.x[3] = data.len();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::TransferToSharedBuffer.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::Transfer {
                source: TransferError::OutOfBounds
            })
        );
    }
    #[test]
    fn transfer_to_shared_buffer_insufficient_permissions() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(302).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(303).unwrap(),
        )
        .unwrap();
        let mem = proc
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
        // READ-only buffer (no WRITE) →  TransferTo must fail.
        let sb = Arc::new(SharedBuffer {
            owner: proc.clone(),
            flags: SharedBufferFlags::READ,
            base_address: mem,
            length: 32,
        });
        let handle = proc.shared_buffers.insert(sb).unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let data = [1u8; 8];
        let mut regs = Registers::default();
        regs.x[0] = handle.get() as usize;
        regs.x[1] = 0; // offset
        regs.x[2] = data.as_ptr() as usize;
        regs.x[3] = data.len(); // within bounds but not permitted

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::TransferToSharedBuffer.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::Transfer {
                source: TransferError::InsufficentPermissions
            })
        );
    }
}
