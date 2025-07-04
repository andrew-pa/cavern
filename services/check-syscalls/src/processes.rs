//! Integration tests for process-related system calls.
#![allow(clippy::cast_possible_truncation)]

use core::{arch::asm, mem::MaybeUninit};

use bytemuck::{bytes_of, cast_slice};
use kernel_api::{
    CallNumber, ErrorCode, ExitMessage, ExitReasonTag, ExitSource, ImageSection, ImageSectionKind,
    PrivilegeLevel, ProcessCreateInfo, ProcessId, QueueId, create_message_queue,
    flags::{ExitNotificationSubscriptionFlags, FreeMessageFlags, ReceiveFlags},
    free_message_queue, kill_process, read_env_value, receive, spawn_process,
};

use crate::{MAIN_QUEUE, Testable};

/// Simple assembly functions used as process entry points.
unsafe extern "C" fn proc_exit_success(_: usize) -> ! {
    unsafe {
        core::arch::asm!(
            "mov x0, #7",
            "svc #0x107", // ExitCurrentThread
            options(noreturn)
        );
    }
}

const PROC_MSG: u32 = u32::from_le_bytes(*b"ping");

unsafe extern "C" fn proc_send_and_exit(qu: usize) -> ! {
    // receive the ID of the parent queue
    let mut result: usize;
    let mut out_len: MaybeUninit<usize> = MaybeUninit::uninit();
    let mut out_msg: MaybeUninit<*mut u8> = MaybeUninit::uninit();
    unsafe {
        asm!(
            "mov x0, {f:x}",
            "mov x1, {q:x}",
            "mov x2, {m:x}",
            "mov x3, {l:x}",
            "svc {call_number}",
            "mov {res}, x0",
            f = in(reg) 0,
            q = in(reg) qu,
            m = in(reg) out_msg.as_mut_ptr(),
            l = in(reg) out_len.as_mut_ptr(),
            res = out(reg) result,
            call_number = const core::mem::transmute::<_,u16>(CallNumber::Receive)
        );
    }
    // exit on fail
    if result != 0 {
        unsafe {
            asm!(
                "mov x0, {r}",
                "svc #0x107",
                r = in(reg) result
            );
        }
    }
    // process message
    let parent_qu: u32 = unsafe {
        u32::from_le_bytes(
            core::slice::from_raw_parts(out_msg.assume_init(), out_len.assume_init())
                .try_into()
                .unwrap(),
        )
    };
    // send the return message and exit
    // TODO: verify
    unsafe {
        asm!(
            "mov x0, {qu:x}",
            // write message to stack and load address in x1
            "sub sp, sp, #8",
            "ldr w1, ={msg}",
            "str w1, [sp]",
            "mov x1, sp",
            // message is 4 bytes
            "mov x2, #4",
            // no shared buffers
            "mov x3, xzr",
            "mov x4, xzr",
            "svc #0x100", // Send TODO: right now we're just sending this to ourselves lol
            "mov x0, #0",
            "svc #0x107", // ExitCurrentThread
            qu = in(reg) parent_qu,
            msg = const PROC_MSG,
            options(noreturn)
        );
    }
}

unsafe extern "C" fn proc_spin(_: usize) -> ! {
    unsafe {
        core::arch::asm!("1: b 1b", options(noreturn));
    }
}

/// Build a minimal [`ProcessCreateInfo`] using a single executable page copied
/// from the current process.
fn mk_proc_info(
    entry: unsafe extern "C" fn(usize) -> !,
    notify: Option<QueueId>,
) -> (ProcessCreateInfo, [ImageSection; 1]) {
    let page_size = read_env_value(kernel_api::EnvironmentValue::PageSizeInBytes);
    let entry_addr = entry as usize;
    let base = entry_addr & !(page_size - 1);
    let entry_offset = entry_addr - base;
    let section = [ImageSection {
        base_address: 0x1000,
        data_offset: 0,
        total_size: page_size,
        data_size: page_size,
        data: base as *const u8,
        kind: ImageSectionKind::Executable,
    }];
    let mq = *MAIN_QUEUE.get().unwrap();
    (
        ProcessCreateInfo {
            entry_point: 0x1000 + entry_offset,
            num_sections: 1,
            sections: section.as_ptr(),
            supervisor: Some(mq),
            registry: Some(mq),
            privilege_level: PrivilegeLevel::Unprivileged,
            notify_on_exit: notify,
            inbox_size: 64,
        },
        section,
    )
}

/// ---
/// Successful spawn with exit notification.
/// ---
fn test_spawn_and_exit_notification() {
    let qid = create_message_queue().expect("queue create");
    let (info, _sections) = mk_proc_info(proc_exit_success, Some(qid));
    let (pid, _child_qid) = spawn_process(&info).expect("spawn failed");

    let msg = receive(ReceiveFlags::empty(), qid).expect("receive failed");
    assert_eq!(msg.header().num_buffers, 0);
    let exit_msg: &ExitMessage = cast_slice(msg.payload()).first().unwrap();
    assert_eq!(exit_msg.source, ExitSource::Process);
    assert_eq!(exit_msg.id, pid.get());
    assert_eq!(exit_msg.reason.tag, ExitReasonTag::User);
    assert_eq!(exit_msg.reason.user_code, 7);

    msg.free(FreeMessageFlags::empty());
    free_message_queue(qid).unwrap();
}

/// ---
/// Spawn a process that sends a message then exits.
/// ---
fn test_spawn_send_message() {
    let qid = create_message_queue().expect("queue create");
    let (info, _sections) = mk_proc_info(proc_send_and_exit, Some(qid));
    let (pid, child_qid) = spawn_process(&info).expect("spawn failed");

    kernel_api::send(child_qid, bytes_of(&qid), &[]).expect("send parent queue to child");

    let first = receive(ReceiveFlags::empty(), qid).expect("receive failed");
    let mut retries = 128;
    let second = loop {
        match receive(ReceiveFlags::NONBLOCKING, qid) {
            Ok(m) => break m,
            Err(ErrorCode::WouldBlock) => {
                retries -= 1;
                assert!(retries != 0, "second message never received");
            }
            Err(e) => panic!("failed to receive second message: {e}"),
        }
    };
    let (msg_proc, msg_exit) = if first.payload().len() == 4 {
        (first, second)
    } else {
        (second, first)
    };

    assert_eq!(msg_proc.payload(), PROC_MSG.to_le_bytes());
    msg_proc.free(FreeMessageFlags::empty());

    let exit_msg: &ExitMessage = cast_slice(msg_exit.payload()).first().unwrap();
    assert_eq!(exit_msg.source, ExitSource::Process);
    assert_eq!(exit_msg.id, pid.get());
    msg_exit.free(FreeMessageFlags::empty());
    free_message_queue(qid).unwrap();
}

/// ---
/// Spawn then kill a running process, expecting a killed exit reason.
/// ---
fn test_kill_process_notification() {
    let qid = create_message_queue().expect("queue create");
    let (info, _sections) = mk_proc_info(proc_spin, Some(qid));
    let (pid, _child_qid) = spawn_process(&info).expect("spawn failed");

    kill_process(pid).expect("kill failed");

    let msg = receive(ReceiveFlags::empty(), qid).expect("receive failed");
    let exit_msg: &ExitMessage = cast_slice(msg.payload()).first().unwrap();
    assert_eq!(exit_msg.source, ExitSource::Process);
    assert_eq!(exit_msg.id, pid.get());
    assert_eq!(exit_msg.reason.tag, ExitReasonTag::Killed);

    msg.free(FreeMessageFlags::empty());
    free_message_queue(qid).unwrap();
}

/// ---
/// Attempting to kill an unknown process must yield `NotFound`.
/// ---
fn test_kill_process_not_found() {
    let fake_pid = ProcessId::new(0x0000_BEEFu32).unwrap();
    match kill_process(fake_pid) {
        Err(ErrorCode::NotFound) => {}
        other => panic!("expected NotFound, got {:?}", other),
    }
}

/// ---
/// Invalid process image pointer ⇒ `InvalidPointer`.
/// ---
#[allow(invalid_value)]
fn test_spawn_null_sections() {
    let info = ProcessCreateInfo {
        entry_point: 0,
        num_sections: 1,
        sections: core::ptr::null(),
        supervisor: None,
        registry: None,
        privilege_level: PrivilegeLevel::Unprivileged,
        notify_on_exit: None,
        inbox_size: 0,
    };
    match spawn_process(&info) {
        Err(ErrorCode::InvalidPointer) => {}
        other => panic!("expected InvalidPointer, got {:?}", other),
    }
}

/// ---
/// Misaligned section base address ⇒ `BadFormat`.
/// ---
fn test_spawn_bad_format() {
    let (mut info, mut sections) = mk_proc_info(proc_exit_success, None);
    sections[0].base_address += 1; // not page aligned
    info.sections = sections.as_ptr();
    match spawn_process(&info) {
        Err(ErrorCode::BadFormat) => {}
        other => panic!("expected BadFormat, got {:?}", other),
    }
}

/// ---
/// Subscribe to a non-existent process ID ⇒ `NotFound`.
/// ---
fn test_exit_sub_unknown_process() {
    let qid = create_message_queue().expect("queue create");
    match kernel_api::exit_notification_subscription(
        ExitNotificationSubscriptionFlags::PROCESS,
        0xBEEF_BEEFu32,
        qid,
    ) {
        Err(ErrorCode::NotFound) => {}
        other => panic!("expected NotFound, got {:?}", other),
    }
    free_message_queue(qid).ok();
}

pub const TESTS: (&str, &[&dyn Testable]) = (
    "processes",
    &[
        &test_spawn_and_exit_notification,
        &test_spawn_send_message,
        &test_kill_process_notification,
        &test_kill_process_not_found,
        &test_spawn_null_sections,
        &test_spawn_bad_format,
        &test_exit_sub_unknown_process,
    ],
);
