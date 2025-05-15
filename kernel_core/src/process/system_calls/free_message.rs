use alloc::sync::Arc;

use kernel_api::{flags::FreeMessageFlags, Message};
use snafu::{OptionExt, ResultExt};

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        PageAllocator, VirtualAddress, VirtualPointer,
    },
    process::{
        queue::QueueManager,
        system_calls::{InvalidAddressSnafu, ManagerSnafu},
        thread::{Registers, ThreadManager},
        ProcessManager, Thread,
    },
};

use super::{Error, InvalidFlagsSnafu, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    #[allow(clippy::unused_self)]
    pub(super) fn syscall_free_message<AUST: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, AUST>,
    ) -> Result<(), Error> {
        let flags = FreeMessageFlags::from_bits(registers.x[0]).context(InvalidFlagsSnafu {
            reason: "invalid bits",
            bits: registers.x[0],
        })?;

        let ptr: VirtualAddress = registers.x[1].into();
        let len = registers.x[2];

        let proc = current_thread.parent.as_ref().unwrap();

        if flags.contains(FreeMessageFlags::FREE_BUFFERS) {
            let msg: &[u8] = user_space_memory
                .check_slice(VirtualPointer::from(ptr).cast(), len)
                .context(InvalidAddressSnafu { cause: "message" })?;
            let msg = unsafe { Message::from_slice(msg) };
            proc.free_shared_buffers(msg.buffers().iter().map(|b| b.buffer))
                .context(ManagerSnafu)?;
        }

        proc.free_message(ptr, len).context(ManagerSnafu)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use std::assert_matches::assert_matches;

    use kernel_api::{
        flags::SharedBufferFlags, CallNumber, MessageHeader, ProcessId, SharedBufferInfo,
    };

    use crate::{
        memory::active_user_space_tables::AlwaysValidActiveUserSpaceTables,
        process::{
            queue::MockQueueManager, system_calls::SysCallEffect, tests::PAGE_ALLOCATOR,
            thread::MockThreadManager, MockProcessManager, Properties, SharedBuffer, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn normal_free_message_no_buffers() {
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(100).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(101).unwrap(),
        )
        .unwrap();

        let current_thread = proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());

        let message = [0u8; 32];
        let mut registers = Registers::default();
        registers.x[0] = 0; // no FREE_BUFFERS flag
        registers.x[1] = message.as_ptr() as usize;
        registers.x[2] = message.len();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::FreeMessage.into_integer(),
                &current_thread,
                &registers,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
    }

    #[test]
    fn free_message_with_buffers_and_flag() {
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(220).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(221).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        // Insert a shared buffer so that the message refers to something real.
        let sb = Arc::new(SharedBuffer {
            owner: proc.clone(),
            flags: SharedBufferFlags::READ | SharedBufferFlags::WRITE,
            base_address: VirtualAddress::null(),
            length: 64,
        });
        let sb_handle = proc.shared_buffers.insert(sb).unwrap();

        // Build a fake inbox message header with one buffer
        let mut msg = [0u8; size_of::<MessageHeader>() + size_of::<SharedBufferInfo>()];
        let hdr = MessageHeader { num_buffers: 1 };
        unsafe {
            core::ptr::write_unaligned(msg.as_mut_ptr() as *mut MessageHeader, hdr);
            let sbi = SharedBufferInfo {
                flags: SharedBufferFlags::READ | SharedBufferFlags::WRITE,
                buffer: sb_handle,
                length: 64,
            };
            core::ptr::write_unaligned(
                msg[size_of::<MessageHeader>()..].as_mut_ptr() as *mut SharedBufferInfo,
                sbi,
            );
        }

        let pa = &*PAGE_ALLOCATOR;
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = FreeMessageFlags::FREE_BUFFERS.bits();
        regs.x[1] = msg.as_ptr() as usize;
        regs.x[2] = msg.len();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::FreeMessage.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
        // Buffer handle should now be gone
        assert!(proc.shared_buffers.get(sb_handle).is_none());
    }
}
