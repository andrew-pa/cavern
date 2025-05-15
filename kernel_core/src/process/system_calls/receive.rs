use alloc::sync::Arc;

use kernel_api::{flags::ReceiveFlags, QueueId};
use snafu::{OptionExt, ResultExt};

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        PageAllocator, VirtualAddress,
    },
    process::{
        queue::QueueManager,
        system_calls::InvalidAddressSnafu,
        thread::{Registers, ThreadManager},
        ProcessManager, Thread,
    },
};

use super::{Error, InvalidFlagsSnafu, InvalidHandleSnafu, SysCallEffect, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    #[allow(clippy::unused_self)]
    pub(super) fn syscall_receive<T: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, T>,
    ) -> Result<SysCallEffect, Error> {
        let flag_bits: usize = registers.x[0];
        let queue_id = QueueId::new(registers.x[1] as _).context(InvalidHandleSnafu {
            reason: "queue id is zero",
            handle: 0u32,
        })?;
        let u_out_msg = registers.x[2].into();
        let out_msg: &mut VirtualAddress =
            user_space_memory
                .check_mut_ref(u_out_msg)
                .context(InvalidAddressSnafu {
                    cause: "output message ptr",
                })?;
        let u_out_len = registers.x[3].into();
        let out_len: &mut usize =
            user_space_memory
                .check_mut_ref(u_out_len)
                .context(InvalidAddressSnafu {
                    cause: "output message len",
                })?;
        let flags = ReceiveFlags::from_bits(flag_bits).context(InvalidFlagsSnafu {
            reason: "invalid bits",
            bits: flag_bits,
        })?;

        let qu = self.queue_by_id_checked(queue_id, current_thread.parent.as_ref().unwrap())?;

        if let Some(msg) = qu.receive() {
            *out_msg = msg.data_address;
            *out_len = msg.data_length;
            Ok(SysCallEffect::Return(0))
        } else if flags.contains(ReceiveFlags::NONBLOCKING) {
            Err(Error::WouldBlock)
        } else {
            current_thread.wait_for_message(qu, u_out_msg, u_out_len);
            Ok(SysCallEffect::ScheduleNextThread)
        }
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use core::mem::MaybeUninit;
    use mockall::predicate::eq;
    use std::assert_matches::assert_matches;

    use kernel_api::{CallNumber, Message, MessageHeader, ProcessId};

    use crate::{
        memory::{active_user_space_tables::AlwaysValidActiveUserSpaceTables, VirtualPointerMut},
        process::{
            queue::{MockQueueManager, PendingMessage},
            system_calls::SysCallEffect,
            tests::PAGE_ALLOCATOR,
            thread::{MockThreadManager, State},
            MessageQueue, MockProcessManager, Properties, QueueId, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn normal_receive_would_block() {
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(7).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(80).unwrap(),
        )
        .unwrap();

        // Create an empty message queue for the process
        let queue = Arc::new(MessageQueue::new(QueueId::new(1).unwrap(), &proc));

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let mut qm = MockQueueManager::new();

        // Expect the queue manager to be queried
        let queue_clone = queue.clone();
        qm.expect_queue_for_id()
            .with(eq(queue.id))
            .return_once(move |_| Some(queue_clone));

        let mut registers = Registers::default();
        registers.x[0] = ReceiveFlags::NONBLOCKING.bits();
        registers.x[1] = queue.id.get() as usize; // Queue ID
        registers.x[2] = 0xabcd; // Output message ptr addr
        registers.x[3] = 0xbcde; // Output message len ptr addr

        let th = proc.threads.read().first().unwrap().clone();

        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert_matches!(
            policy.dispatch_system_call(CallNumber::Receive.into_integer(), &th, &registers, &usm),
            Err(Error::WouldBlock)
        );
    }
    #[test]
    fn normal_receive_block() {
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(7).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(80).unwrap(),
        )
        .unwrap();

        // Create an empty message queue for the process
        let queue = Arc::new(MessageQueue::new(QueueId::new(1).unwrap(), &proc));

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let mut qm = MockQueueManager::new();

        // Expect the queue manager to be queried
        let queue_clone = queue.clone();
        qm.expect_queue_for_id()
            .with(eq(queue.id))
            .return_once(move |_| Some(queue_clone));

        let mut registers = Registers::default();
        registers.x[0] = ReceiveFlags::empty().bits();
        registers.x[1] = queue.id.get() as usize; // Queue ID
        registers.x[2] = 0xabcd; // Output message ptr addr
        registers.x[3] = 0xbcde; // Output message len ptr addr

        let th = proc.threads.read().first().unwrap().clone();

        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert_matches!(
            policy.dispatch_system_call(CallNumber::Receive.into_integer(), &th, &registers, &usm),
            Ok(SysCallEffect::ScheduleNextThread)
        );

        assert_eq!(th.state(), State::WaitingForMessage);
        assert_eq!(
            th.pending_message_receive_queue.lock().as_ref().unwrap().id,
            queue.id
        );
        let pmr = th.pending_message_receive.lock();
        assert_eq!(
            *pmr,
            Some((
                VirtualPointerMut::from(0xabcd),
                VirtualPointerMut::from(0xbcde)
            ))
        );
    }
    #[test]
    fn normal_receive_immediate() {
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(7).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(80).unwrap(),
        )
        .unwrap();
        let th = proc.threads.read().first().unwrap().clone();

        // Create a message queue and add a message to it
        let queue = Arc::new(MessageQueue::new(QueueId::new(1).unwrap(), &proc));

        let mut message = [0u8; 64];

        let pending_msg = PendingMessage {
            data_address: VirtualPointerMut::from(message.as_mut_ptr()).cast(),
            data_length: message.len(),
        };
        // Manually write a dummy header (sender info isn't stored in PendingMessage)
        let header = MessageHeader { num_buffers: 0 };
        unsafe {
            core::ptr::copy_nonoverlapping(
                &header as *const _ as *const u8,
                message.as_mut_ptr(),
                size_of::<MessageHeader>(),
            );
        }
        queue.pending.push(pending_msg);

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let mut qm = MockQueueManager::new();

        // Expect the queue manager to be queried
        let queue_clone = queue.clone();
        qm.expect_queue_for_id()
            .with(eq(queue.id))
            .return_once(move |_| Some(queue_clone));

        let mut msg_ptr: MaybeUninit<*mut ()> = MaybeUninit::uninit();
        let mut msg_len: MaybeUninit<usize> = MaybeUninit::uninit();

        let mut registers = Registers::default();
        registers.x[0] = ReceiveFlags::empty().bits();
        registers.x[1] = queue.id.get() as usize; // Queue ID
        registers.x[2] = msg_ptr.as_mut_ptr() as usize; // Output message ptr addr
        registers.x[3] = msg_len.as_mut_ptr() as usize; // Output message len ptr addr

        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert_matches!(
            policy.dispatch_system_call(CallNumber::Receive.into_integer(), &th, &registers, &usm),
            Ok(SysCallEffect::Return(0))
        );

        unsafe {
            assert_eq!(msg_ptr.assume_init(), message.as_mut_ptr() as _);
            assert_eq!(msg_len.assume_init(), message.len());
        }
        // Check header content (sender info isn't available here anymore)
        let msg = unsafe { Message::from_slice(&message[..size_of::<MessageHeader>()]) };
        assert_eq!(msg.header().num_buffers, 0);
    }
}
