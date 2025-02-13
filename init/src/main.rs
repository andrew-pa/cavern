//! The Cavern `init` process.
//!
//! The `init` process is responsible for starting up user space.
#![no_std]
#![no_main]
#![deny(missing_docs)]
#![allow(clippy::cast_possible_truncation)]

use kernel_api::{
    KERNEL_FAKE_PID, ProcessId, ThreadCreateInfo, allocate_heap_pages, exit_current_thread,
    exit_notification_subscription,
    flags::{ExitNotificationSubscriptionFlags, ReceiveFlags},
    free_heap_pages, receive, send, spawn_thread,
};

fn thread2(arg: usize) -> ! {
    let thread_id = kernel_api::read_env_value(kernel_api::EnvironmentValue::CurrentThreadId);
    let msg = receive(ReceiveFlags::empty()).expect("receive message");
    assert_eq!(msg.payload(), b"Hello!");
    exit_current_thread((thread_id + 1 + arg) as u32);
}

/// The main entry point.
///
/// # Panics
/// Right now we panic if any errors happen.
#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let process_id = ProcessId::new(kernel_api::read_env_value(
        kernel_api::EnvironmentValue::CurrentProcessId,
    ) as u32)
    .unwrap();

    spawn_thread(&ThreadCreateInfo {
        entry: thread2,
        stack_size: 0,
        user_data: 0,
    })
    .expect_err("spawn thread");

    spawn_thread(unsafe {
        (0xffff_0000_ffff_0000 as *const ThreadCreateInfo)
            .as_ref()
            .unwrap()
    })
    .expect_err("spawn thread");

    let tid = spawn_thread(&ThreadCreateInfo {
        entry: thread2,
        stack_size: 1,
        user_data: 7000,
    })
    .expect("spawn thread");

    exit_notification_subscription(ExitNotificationSubscriptionFlags::THREAD, tid.get(), None)
        .expect("subscribe to exit");

    let p = allocate_heap_pages(1).expect("allocate");
    unsafe {
        p.write(0xab);
    }
    free_heap_pages(p, 1).expect("free");

    send(process_id, Some(tid), b"Hello!", &[]).expect("send message");

    let exit_msg = receive(ReceiveFlags::empty()).expect("receive exit message");
    assert_eq!(exit_msg.header().sender_pid, KERNEL_FAKE_PID);
    assert_eq!(exit_msg.header().sender_tid, tid);

    exit_current_thread(process_id.get() + 1);
}

/// The panic handler.
#[panic_handler]
pub fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    exit_current_thread(1);
}
