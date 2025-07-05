//! Integration tests for process-related system calls.
#![allow(clippy::cast_possible_truncation)]

use core::{
    arch::{asm, naked_asm},
    mem::MaybeUninit,
};

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

#[unsafe(naked)]
unsafe extern "C" fn proc_send_and_exit(_qu: usize) -> ! {
    naked_asm!(
        "mov x9, x0      // save parent queue id",
        "sub sp, sp, #32 // allocate stack space for receive outputs and send buffer",
        "mov x0, #0      // receive flags = 0",
        "mov x1, x9      // queue id for receive",
        "mov x2, sp      // out_msg ptr",
        "add x3, sp, #8  // out_len ptr",
        "svc #0x101     // syscall Receive",
        "cmp x0, #0      // check result",
        "b.ne 1f         // if non-zero error, jump to exit",
        "ldr x5, [sp]    // load out_msg pointer",
        "add x5, x5, #8", //skip the message header
        "ldr w0, [x5]    // read parent queue id from message",
        "add x6, sp, #16 // buffer for send payload",
        "ldr w1, ={msg}  // load PROC_MSG constant",
        "str w1, [x6]    // store payload word",
        "mov x1, x6      // send payload ptr",
        "mov x2, #4      // payload length = 4",
        "mov x3, xzr     // no shared buffers",
        "mov x4, xzr     // no flags",
        "svc #0x100     // syscall Send",
        "mov x0, #0      // exit code = 0",
        "svc #0x107     // syscall ExitCurrentThread",
        "1:",
        "svc #0x107     // exit on error (x0 holds error)",
        msg = const PROC_MSG,
    );
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
/// Misaligned section base address ⇒ `InvalidPointer`.
/// ---
fn test_spawn_bad_format() {
    let (mut info, mut sections) = mk_proc_info(proc_exit_success, None);
    sections[0].base_address += 1; // not page aligned
    info.sections = sections.as_ptr();
    match spawn_process(&info) {
        Err(ErrorCode::InvalidPointer) => {}
        other => panic!("expected InvalidPointer, got {:?}", other),
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
