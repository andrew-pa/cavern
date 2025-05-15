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
    pub(super) fn syscall_transfer_from<AUST: ActiveUserSpaceTables>(
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
        let dst = user_space_memory
            .check_slice_mut(registers.x[2].into(), registers.x[3])
            .context(InvalidAddressSnafu {
                cause: "destination buffer",
            })?;
        buf.transfer_from(offset, dst).context(TransferSnafu)
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
    fn normal_transfer_from_shared_buffer() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(80).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(81).unwrap(),
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
            flags: kernel_api::flags::SharedBufferFlags::READ,
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

        let mut dst_data = [0u8; 4];
        let mut registers = Registers::default();
        registers.x[0] = handle.get() as usize;
        registers.x[1] = 0; // offset
        registers.x[2] = dst_data.as_mut_ptr() as usize;
        registers.x[3] = dst_data.len();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::TransferFromSharedBuffer.into_integer(),
                &current_thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
    }
    #[test]
    fn transfer_from_shared_buffer_out_of_bounds() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(300).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(301).unwrap(),
        )
        .unwrap();
        // Shared buffer: READ-only, length 32.
        let mem = proc
            .allocate_memory(
                pa,
                1,
                MemoryProperties {
                    owned: true,
                    user_space_access: true,
                    writable: false,
                    ..Default::default()
                },
            )
            .unwrap();
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

        let mut dst = [0u8; 32];
        let mut regs = Registers::default();
        regs.x[0] = handle.get() as usize;
        regs.x[1] = 16; // offset
        regs.x[2] = dst.as_mut_ptr() as usize;
        regs.x[3] = dst.len(); // 16 + 32 > 32 → OOB

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::TransferFromSharedBuffer.into_integer(),
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
    fn transfer_from_shared_buffer_insufficient_permissions() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(304).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(305).unwrap(),
        )
        .unwrap();
        let mem = proc
            .allocate_memory(
                pa,
                1,
                MemoryProperties {
                    owned: true,
                    user_space_access: true,
                    writable: false,
                    ..Default::default()
                },
            )
            .unwrap();
        // WRITE-only buffer (no READ) → TransferFrom must fail.
        let sb = Arc::new(SharedBuffer {
            owner: proc.clone(),
            flags: SharedBufferFlags::WRITE,
            base_address: mem,
            length: 16,
        });
        let handle = proc.shared_buffers.insert(sb).unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut dst = [0u8; 4];
        let mut regs = Registers::default();
        regs.x[0] = handle.get() as usize;
        regs.x[1] = 0; // offset
        regs.x[2] = dst.as_mut_ptr() as usize;
        regs.x[3] = dst.len();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::TransferFromSharedBuffer.into_integer(),
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
