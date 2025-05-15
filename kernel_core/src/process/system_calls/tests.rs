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
