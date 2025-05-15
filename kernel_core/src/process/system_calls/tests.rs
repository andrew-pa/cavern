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

// 9 ────────────────────────────────────────────────────────────────────────────
