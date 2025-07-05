use alloc::{format, sync::Arc};

use kernel_api::{ProcessId, QueueId, SharedBufferCreateInfo};
use log::{debug, trace};
use snafu::{ensure, OptionExt, ResultExt};

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        PageAllocator, VirtualAddress,
    },
    process::{
        queue::QueueManager,
        system_calls::{InvalidAddressSnafu, InvalidLengthSnafu, ManagerSnafu, NotFoundSnafu},
        thread::{Registers, ThreadManager},
        ProcessManager, SharedBuffer, Thread,
    },
};

use super::{Error, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    pub(super) fn syscall_send<T: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, T>,
    ) -> Result<(), Error> {
        let dst_queue_id: Option<QueueId> = QueueId::new(registers.x[0] as _);
        let message = user_space_memory
            .check_slice(registers.x[1].into(), registers.x[2])
            .context(InvalidAddressSnafu { cause: "message" })?;
        let buffers: &[SharedBufferCreateInfo] = user_space_memory
            .check_slice(registers.x[3].into(), registers.x[4])
            .context(InvalidAddressSnafu { cause: "buffers" })?;
        ensure!(
            !message.is_empty() || !buffers.is_empty(),
            InvalidLengthSnafu {
                reason: "message must have at least non-zero size or non-zero number of buffers",
                length: 0usize
            }
        );
        let dst = dst_queue_id
            .and_then(|qid| self.queue_manager.queue_for_id(qid))
            .context(NotFoundSnafu {
                reason: "destination queue id",
                id: dst_queue_id.map_or(0, ProcessId::get) as usize,
            })?;
        let current_proc = current_thread.parent.as_ref().unwrap();
        debug!(
            "process #{} sending message to queue #{}",
            current_proc.id, dst.id
        );
        if !buffers.is_empty() {
            trace!("sending buffers {buffers:?}");
        }
        dst.send(
            message,
            buffers.iter().map(|b| {
                Arc::new(SharedBuffer {
                    owner: current_proc.clone(),
                    flags: b.flags,
                    base_address: VirtualAddress::from(b.base_address.cast()),
                    length: b.length,
                })
            }),
        )
        .with_context(|_| ManagerSnafu {
            reason: format!("sending message to queue #{}", dst.id),
        })
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use mockall::predicate::eq;
    use std::assert_matches::assert_matches;

    use kernel_api::{
        flags::SharedBufferFlags, CallNumber, Message, MessageHeader, ProcessId, SharedBufferInfo,
    };

    use crate::{
        memory::active_user_space_tables::AlwaysValidActiveUserSpaceTables,
        process::{
            queue::MockQueueManager, system_calls::SysCallEffect, tests::PAGE_ALLOCATOR,
            thread::MockThreadManager, MessageQueue, MockProcessManager, Properties, QueueId,
            ThreadId,
        },
    };

    use super::*;

    #[test]
    fn normal_send() {
        let sender_proc = crate::process::tests::create_test_process(
            ProcessId::new(7).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(80).unwrap(),
        )
        .unwrap();
        let receiver_proc = crate::process::tests::create_test_process(
            ProcessId::new(8).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(81).unwrap(),
        )
        .unwrap();

        // Create a message queue for the receiver process
        let receiver_queue = Arc::new(MessageQueue::new(QueueId::new(1).unwrap(), &receiver_proc));

        let message = b"Hello, world!!";
        let buffers = &[SharedBufferCreateInfo {
            flags: SharedBufferFlags::READ,
            base_address: 0x1fff as _,
            length: 1234,
        }];

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let mut qm = MockQueueManager::new();

        // Expect the queue manager to be queried for the destination queue
        let receiver_queue_clone = receiver_queue.clone();
        qm.expect_queue_for_id()
            .with(eq(receiver_queue.id))
            .return_once(move |_| Some(receiver_queue_clone));

        let mut registers = Registers::default();
        registers.x[0] = receiver_queue.id.get() as usize; // Destination Queue ID
        registers.x[1] = message.as_ptr() as usize;
        registers.x[2] = message.len();
        registers.x[3] = buffers.as_ptr() as usize;
        registers.x[4] = buffers.len();

        let th = sender_proc.threads.read().first().unwrap().clone();

        let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
        assert_matches!(
            policy.dispatch_system_call(CallNumber::Send.into_integer(), &th, &registers, &usm),
            Ok(SysCallEffect::Return(0))
        );

        // Check that the message arrived in the queue
        let msg = receiver_queue
            .receive()
            .expect("message should be in queue");
        assert_eq!(
            msg.data_length,
            message.len() + size_of::<MessageHeader>() + size_of::<SharedBufferInfo>()
        );

        // Check the shared buffer was added to the receiver process
        // We need to parse the message header to find the handle
        let mut header_data = [0u8; size_of::<MessageHeader>() + size_of::<SharedBufferInfo>()];
        unsafe {
            receiver_proc
                .page_tables
                .read()
                .copy_from_while_unmapped(msg.data_address, &mut header_data)
                .unwrap();
        }
        let msg_parsed = unsafe { Message::from_slice(&header_data) }; // Only need header part
        let buf_info = msg_parsed
            .buffers()
            .first()
            .expect("message has shared buffer");
        let buf_hdl = buf_info.buffer;

        let buf = receiver_proc
            .shared_buffers
            .get(buf_hdl)
            .expect("get buffer by handle");
        assert_eq!(buf.owner.id, sender_proc.id);
        assert!(buf.flags.symmetric_difference(buffers[0].flags).is_empty());
        assert_eq!(buf.base_address, (buffers[0].base_address as usize).into());
        assert_eq!(buf.length, buffers[0].length);

        let mut message_data_check = [0u8; 14];
        unsafe {
            receiver_proc
                .page_tables
                .read()
                .copy_from_while_unmapped(
                    msg.data_address
                        .byte_add(size_of::<MessageHeader>() + size_of::<SharedBufferInfo>()),
                    &mut message_data_check,
                )
                .unwrap();
        }
        assert_eq!(&message_data_check, message);
    }
    #[test]
    fn send_zero_length_message_invalid_length() {
        let pa = &*PAGE_ALLOCATOR;
        let sender = crate::process::tests::create_test_process(
            ProcessId::new(312).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(313).unwrap(),
        )
        .unwrap();
        let receiver = crate::process::tests::create_test_process(
            ProcessId::new(314).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(315).unwrap(),
        )
        .unwrap();
        // Receiver owns a queue we know about.
        let queue = Arc::new(MessageQueue::new(QueueId::new(0xbeef).unwrap(), &receiver));

        // Queue-manager mock.
        let mut qm = MockQueueManager::new();
        let queue2 = queue.clone();
        qm.expect_queue_for_id()
            .with(eq(queue.id))
            .return_once(move |_| Some(queue2));

        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let current_thread = sender.threads.read().first().unwrap().clone();
        let mut regs = Registers::default();
        regs.x[0] = queue.id.get() as usize; // dst queue
        regs.x[1] = core::ptr::null::<u8>() as usize;
        regs.x[2] = 0; // zero-length message
        regs.x[3] = core::ptr::null::<u8>() as usize;
        regs.x[4] = 0; // no buffers

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::Send.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::InvalidLength { .. })
        );
    }
}
