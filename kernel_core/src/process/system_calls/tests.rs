//! Unit tests for system calls.

use core::{mem::MaybeUninit, num::NonZeroU32, ptr};
use std::assert_matches::assert_matches;

use kernel_api::{flags::SharedBufferFlags, MessageHeader, SharedBufferInfo};
use mockall::predicate::{eq, function};

use crate::{
    memory::{
        active_user_space_tables::{AlwaysValidActiveUserSpaceTables, MockActiveUserSpaceTables},
        page_table::MemoryProperties,
        MockPageAllocator, VirtualAddress, VirtualPointerMut,
    },
    process::{
        queue::{MessageQueue, MockQueueManager},
        tests::PAGE_ALLOCATOR,
        thread::{MockThreadManager, State},
        MockProcessManager, PendingMessage, Properties, QueueId, SharedBuffer,
    },
};

use super::*;

pub fn fake_thread() -> Arc<Thread> {
    Arc::new(Thread::new(
        NonZeroU32::new(777).unwrap(),
        None,
        crate::process::thread::State::Running,
        crate::process::thread::ProcessorState::new_for_user_thread(
            VirtualAddress::null(),
            VirtualAddress::null(),
            0,
        ),
        (VirtualAddress::null(), 0),
    ))
}

#[test]
fn invalid_syscall_number() {
    let pa = MockPageAllocator::new();
    let pm = MockProcessManager::new();
    let mut tm = MockThreadManager::new();
    let qm = MockQueueManager::new();

    let thread = fake_thread();

    // invalid syscall number -> thread fault
    let thread2 = thread.clone();
    tm.expect_exit_thread()
        .once()
        .withf(move |t, r| t.id == thread2.id && *r == ExitReason::invalid_syscall())
        .returning(|_, _| false);

    let policy = SystemCalls::new(&pa, &pm, &tm, &qm);

    let usm = MockActiveUserSpaceTables::new();

    let registers = Registers::default();

    let system_call_number_that_is_invalid = 1;
    assert_matches!(
        policy.dispatch_system_call(
            system_call_number_that_is_invalid,
            &thread,
            &registers,
            &usm
        ),
        Ok(SysCallEffect::ScheduleNextThread)
    );
}

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
fn normal_exit_notification_subscription_process() {
    let current_proc = crate::process::tests::create_test_process(
        ProcessId::new(120).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(121).unwrap(),
    )
    .unwrap();

    let current_thread = current_proc.threads.read().first().unwrap().clone();

    let queue_id = QueueId::new(1234).unwrap();
    let queue = Arc::new(MessageQueue::new(queue_id, &current_proc));

    // Create a target process for exit subscription.
    let target_proc = crate::process::tests::create_test_process(
        ProcessId::new(130).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(131).unwrap(),
    )
    .unwrap();

    let mut pm = MockProcessManager::new();
    let tp2 = target_proc.clone();
    pm.expect_process_for_id()
        .with(eq(target_proc.id))
        .return_once(move |_| Some(tp2));

    let mut qm = MockQueueManager::new();
    qm.expect_queue_for_id()
        .with(eq(queue_id))
        .return_once(|_| Some(queue));

    let flags = ExitNotificationSubscriptionFlags::PROCESS;

    let mut registers = Registers::default();
    registers.x[0] = flags.bits();
    registers.x[1] = target_proc.id.get() as usize;
    registers.x[2] = queue_id.get() as usize;

    let tm = MockThreadManager::new();
    let policy = SystemCalls::new(&*PAGE_ALLOCATOR, &pm, &tm, &qm);
    let usm = AlwaysValidActiveUserSpaceTables::new(PAGE_ALLOCATOR.page_size());
    assert_matches!(
        policy.dispatch_system_call(
            CallNumber::ExitNotificationSubscription.into_integer(),
            &current_thread,
            &registers,
            &usm
        ),
        Ok(SysCallEffect::Return(0))
    );
    let subs = target_proc.exit_subscribers.lock();
    assert!(subs.iter().any(|q| q.id == queue_id));
}

#[test]
fn normal_exit_notification_subscription_thread() {
    let pa = &*PAGE_ALLOCATOR;
    let proc = crate::process::tests::create_test_process(
        ProcessId::new(140).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(141).unwrap(),
    )
    .unwrap();

    // Create an extra thread in the process.
    let extra_thread = fake_thread();
    proc.threads.write().push(extra_thread.clone());

    let queue_id = QueueId::new(1234).unwrap();
    let queue = Arc::new(MessageQueue::new(queue_id, &proc));

    let current_thread = proc.threads.read().first().unwrap().clone();
    let pm = MockProcessManager::new();
    let ex = extra_thread.clone();
    let mut tm = MockThreadManager::new();
    tm.expect_thread_for_id()
        .with(eq(extra_thread.id))
        .return_once(|_| Some(ex));
    let mut qm = MockQueueManager::new();
    qm.expect_queue_for_id()
        .with(eq(queue_id))
        .return_once(|_| Some(queue));
    let policy = SystemCalls::new(pa, &pm, &tm, &qm);
    let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

    let flags = ExitNotificationSubscriptionFlags::THREAD;

    let mut registers = Registers::default();
    registers.x[0] = flags.bits();
    registers.x[1] = extra_thread.id.get() as usize;
    registers.x[2] = queue_id.get() as usize;

    assert_matches!(
        policy.dispatch_system_call(
            CallNumber::ExitNotificationSubscription.into_integer(),
            &current_thread,
            &registers,
            &usm
        ),
        Ok(SysCallEffect::Return(0))
    );
    let subs = extra_thread.exit_subscribers.lock();
    assert!(subs.iter().any(|q| q.id == queue_id));
}

// --- Message-queue syscalls -------------------------------------------------------------

#[test]
fn create_message_queue_success() {
    let pa = &*PAGE_ALLOCATOR;
    let proc = crate::process::tests::create_test_process(
        ProcessId::new(200).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(201).unwrap(),
    )
    .unwrap();
    let current_thread = proc.threads.read().first().unwrap().clone();

    // Queue-manager mock: expect one queue creation for `proc`
    let mut qm = MockQueueManager::new();
    let new_qid = QueueId::new(0xdead).unwrap();
    qm.expect_create_queue()
        .with(function(move |owner: &Arc<Process>| {
            Arc::ptr_eq(owner, &proc)
        }))
        .return_once(move |owner| Ok(Arc::new(MessageQueue::new(new_qid.into(), &owner))));

    let pm = MockProcessManager::new();
    let tm = MockThreadManager::new();
    let policy = SystemCalls::new(pa, &pm, &tm, &qm);
    let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

    let mut out_qid = MaybeUninit::<QueueId>::uninit();
    let mut regs = Registers::default();
    regs.x[1] = &mut out_qid as *mut _ as usize;

    assert_matches!(
        policy.dispatch_system_call(
            CallNumber::CreateMessageQueue.into_integer(),
            &current_thread,
            &regs,
            &usm
        ),
        Ok(SysCallEffect::Return(0))
    );
    assert_eq!(unsafe { out_qid.assume_init() }, new_qid);
}

#[test]
fn create_message_queue_bad_ptr() {
    let pa = &*PAGE_ALLOCATOR;
    let proc = crate::process::tests::create_test_process(
        ProcessId::new(202).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(203).unwrap(),
    )
    .unwrap();
    let current_thread = proc.threads.read().first().unwrap().clone();

    let pm = MockProcessManager::new();
    let tm = MockThreadManager::new();
    let qm = MockQueueManager::new();
    let policy = SystemCalls::new(pa, &pm, &tm, &qm);
    let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

    let mut regs = Registers::default();
    regs.x[1] = 0; // null pointer ⇒ invalid

    assert_matches!(
        policy.dispatch_system_call(
            CallNumber::CreateMessageQueue.into_integer(),
            &current_thread,
            &regs,
            &usm
        ),
        Err(Error::InvalidAddress { .. })
    );
}

#[test]
fn free_message_queue_success() {
    let pa = &*PAGE_ALLOCATOR;
    let proc = crate::process::tests::create_test_process(
        ProcessId::new(210).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(211).unwrap(),
    )
    .unwrap();
    let current_thread = proc.threads.read().first().unwrap().clone();

    // Pre-create a queue that will be freed
    let qid = QueueId::new(0xbeef).unwrap();
    let queue = Arc::new(MessageQueue::new(qid.into(), &proc));

    let mut qm = MockQueueManager::new();
    let queue2 = queue.clone();
    qm.expect_queue_for_id()
        .with(eq(qid))
        .return_once(move |_| Some(queue2));
    qm.expect_free_queue()
        .with(function(move |q: &Arc<MessageQueue>| {
            Arc::ptr_eq(q, &queue)
        }))
        .return_once(|_| ());

    let pm = MockProcessManager::new();
    let tm = MockThreadManager::new();
    let policy = SystemCalls::new(pa, &pm, &tm, &qm);
    let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

    let mut regs = Registers::default();
    regs.x[0] = qid.get() as usize;

    assert_matches!(
        policy.dispatch_system_call(
            CallNumber::FreeMessageQueue.into_integer(),
            &current_thread,
            &regs,
            &usm
        ),
        Ok(SysCallEffect::Return(0))
    );
}

#[test]
fn free_message_queue_not_found() {
    let pa = &*PAGE_ALLOCATOR;
    let proc = crate::process::tests::create_test_process(
        ProcessId::new(212).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(213).unwrap(),
    )
    .unwrap();
    let current_thread = proc.threads.read().first().unwrap().clone();

    let mut qm = MockQueueManager::new();
    qm.expect_queue_for_id().return_const(None);

    let pm = MockProcessManager::new();
    let tm = MockThreadManager::new();
    let policy = SystemCalls::new(pa, &pm, &tm, &qm);
    let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

    let mut regs = Registers::default();
    regs.x[0] = 0x9999; // unknown id

    assert_matches!(
        policy.dispatch_system_call(
            CallNumber::FreeMessageQueue.into_integer(),
            &current_thread,
            &regs,
            &usm
        ),
        Err(Error::NotFound { .. })
    );
}

// --- `free_message` with FREE_BUFFERS ---------------------------------------------------

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
        ptr::write_unaligned(msg.as_mut_ptr() as *mut MessageHeader, hdr);
        let sbi = SharedBufferInfo {
            flags: SharedBufferFlags::READ | SharedBufferFlags::WRITE,
            buffer: sb_handle,
            length: 64,
        };
        ptr::write_unaligned(
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

// --- Logger syscall --------------------------------------------------------------------

#[test]
fn write_log_success() {
    let proc = crate::process::tests::create_test_process(
        ProcessId::new(230).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(231).unwrap(),
    )
    .unwrap();
    let current_thread = proc.threads.read().first().unwrap().clone();

    let pa = &*PAGE_ALLOCATOR;
    let pm = MockProcessManager::new();
    let tm = MockThreadManager::new();
    let qm = MockQueueManager::new();
    let policy = SystemCalls::new(pa, &pm, &tm, &qm);
    let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

    let msg = b"hello-logger";
    let mut regs = Registers::default();
    regs.x[0] = 3; // Info level
    regs.x[1] = msg.as_ptr() as usize;
    regs.x[2] = msg.len();

    assert_matches!(
        policy.dispatch_system_call(
            CallNumber::WriteLogMessage.into_integer(),
            &current_thread,
            &regs,
            &usm
        ),
        Ok(SysCallEffect::Return(0))
    );
}

#[test]
fn write_log_invalid_level() {
    let proc = crate::process::tests::create_test_process(
        ProcessId::new(232).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(233).unwrap(),
    )
    .unwrap();
    let current_thread = proc.threads.read().first().unwrap().clone();

    let pa = &*PAGE_ALLOCATOR;
    let pm = MockProcessManager::new();
    let tm = MockThreadManager::new();
    let qm = MockQueueManager::new();
    let policy = SystemCalls::new(pa, &pm, &tm, &qm);
    let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

    let mut regs = Registers::default();
    regs.x[0] = 7; // invalid level (allowed 1-5)
    regs.x[1] = b"x".as_ptr() as usize;
    regs.x[2] = 1;

    assert_matches!(
        policy.dispatch_system_call(
            CallNumber::WriteLogMessage.into_integer(),
            &current_thread,
            &regs,
            &usm
        ),
        Err(Error::InvalidFlags { .. })
    );
}

// --- Exit-notification UNSUBSCRIBE -----------------------------------------------------

#[test]
fn exit_notification_unsubscribe() {
    let current_proc = crate::process::tests::create_test_process(
        ProcessId::new(240).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(241).unwrap(),
    )
    .unwrap();
    let current_thread = current_proc.threads.read().first().unwrap().clone();

    // Queue to remove
    let qid = QueueId::new(0xcafe).unwrap();
    let queue = Arc::new(MessageQueue::new(qid.into(), &current_proc));
    current_proc.exit_subscribers.lock().push(queue.clone());

    let mut qm = MockQueueManager::new();
    qm.expect_queue_for_id()
        .with(eq(qid))
        .return_once(|_| Some(queue));

    let pa = &*PAGE_ALLOCATOR;
    let mut pm = MockProcessManager::new();
    let cp2 = current_proc.clone();
    pm.expect_process_for_id()
        .with(eq(current_proc.id))
        .return_once(|_| Some(cp2));
    let tm = MockThreadManager::new();
    let policy = SystemCalls::new(pa, &pm, &tm, &qm);
    let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

    let mut regs = Registers::default();
    regs.x[0] = (ExitNotificationSubscriptionFlags::UNSUBSCRIBE
        | ExitNotificationSubscriptionFlags::PROCESS)
        .bits();
    regs.x[1] = current_proc.id.get() as usize;
    regs.x[2] = qid.get() as usize;

    assert_matches!(
        policy.dispatch_system_call(
            CallNumber::ExitNotificationSubscription.into_integer(),
            &current_thread,
            &regs,
            &usm
        ),
        Ok(SysCallEffect::Return(0))
    );
    assert!(current_proc.exit_subscribers.lock().is_empty());
}

#[test]
fn exit_notification_invalid_flags() {
    let proc = crate::process::tests::create_test_process(
        ProcessId::new(242).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(243).unwrap(),
    )
    .unwrap();
    let current_thread = proc.threads.read().first().unwrap().clone();

    let pa = &*PAGE_ALLOCATOR;
    let pm = MockProcessManager::new();
    let tm = MockThreadManager::new();
    let qm = MockQueueManager::new();
    let policy = SystemCalls::new(pa, &pm, &tm, &qm);
    let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

    let mut regs = Registers::default();
    regs.x[0] = (ExitNotificationSubscriptionFlags::PROCESS
        | ExitNotificationSubscriptionFlags::THREAD)
        .bits();
    regs.x[1] = 0;
    regs.x[2] = 0;

    assert_matches!(
        policy.dispatch_system_call(
            CallNumber::ExitNotificationSubscription.into_integer(),
            &current_thread,
            &regs,
            &usm
        ),
        Err(Error::InvalidFlags { .. })
    );
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
            source: ManagerError::Missing { .. }
        })
    );
}

// 9 ────────────────────────────────────────────────────────────────────────────
#[test]
fn create_message_queue_out_of_handles() {
    let pa = &*PAGE_ALLOCATOR;
    let proc = crate::process::tests::create_test_process(
        ProcessId::new(318).unwrap(),
        Properties {
            supervisor_queue: None,
            registry_queue: None,
            privilege: kernel_api::PrivilegeLevel::Privileged,
        },
        ThreadId::new(319).unwrap(),
    )
    .unwrap();
    let current_thread = proc.threads.read().first().unwrap().clone();

    // Queue-manager mock: no handles left.
    let mut qm = MockQueueManager::new();
    qm.expect_create_queue()
        .returning(|_| Err(ManagerError::OutOfHandles));

    let pm = MockProcessManager::new();
    let tm = MockThreadManager::new();
    let policy = SystemCalls::new(pa, &pm, &tm, &qm);
    let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

    let mut out_qid = MaybeUninit::<QueueId>::uninit();
    let mut regs = Registers::default();
    regs.x[1] = &mut out_qid as *mut _ as usize;

    assert_matches!(
        policy.dispatch_system_call(
            CallNumber::CreateMessageQueue.into_integer(),
            &current_thread,
            &regs,
            &usm
        ),
        Err(Error::Manager {
            source: ManagerError::OutOfHandles
        })
    );
}
