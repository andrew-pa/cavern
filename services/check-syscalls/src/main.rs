//! A quick test to make sure that system calls operate as expected.
#![no_std]
#![no_main]
#![deny(missing_docs)]
#![allow(clippy::cast_possible_truncation)]

use kernel_api::{
    ExitMessage, ExitReasonTag, ExitSource, KERNEL_FAKE_PID, ProcessId, SharedBufferCreateInfo,
    ThreadCreateInfo, allocate_heap_pages, exit_current_thread, exit_notification_subscription,
    flags::{ExitNotificationSubscriptionFlags, FreeMessageFlags, ReceiveFlags, SharedBufferFlags},
    free_heap_pages, free_message, receive, send, spawn_thread, transfer_from_shared_buffer,
    transfer_to_shared_buffer, write_log,
};

fn thread2(arg: usize) -> ! {
    write_log(3, "hello from user space, thread 2!").unwrap();
    let thread_id = kernel_api::read_env_value(kernel_api::EnvironmentValue::CurrentThreadId);
    let msg = receive(ReceiveFlags::empty()).expect("receive message");
    assert_eq!(msg.payload(), b"Hello!");
    let buf = msg.buffers().first().unwrap();
    assert_eq!(buf.length, 8);
    let mut data = [0u8];
    transfer_from_shared_buffer(buf.buffer, 0, &mut data).expect("read byte");
    assert_eq!(data[0], 0xab);
    data[0] = 0xef;
    transfer_to_shared_buffer(buf.buffer, 0, &data).expect("write byte");
    free_message(FreeMessageFlags::FREE_BUFFERS, msg).expect("free message");
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

    write_log(3, "hello from user space!").unwrap();

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

    send(
        process_id,
        Some(tid),
        b"Hello!",
        &[SharedBufferCreateInfo {
            flags: SharedBufferFlags::READ | SharedBufferFlags::WRITE,
            base_address: p,
            length: 8,
        }],
    )
    .expect("send message");

    let exit_msg = receive(ReceiveFlags::empty()).expect("receive exit message");
    assert_eq!(exit_msg.header().sender_pid, KERNEL_FAKE_PID);
    assert_eq!(exit_msg.header().sender_tid, tid);
    let em: &ExitMessage = bytemuck::from_bytes(exit_msg.payload());
    assert_eq!(em.source, ExitSource::Thread);
    assert_eq!(em.reason.tag, ExitReasonTag::User);
    assert_eq!(em.reason.user_code, 7000 + tid.get() + 1);
    free_message(FreeMessageFlags::FREE_BUFFERS, exit_msg).expect("free message");

    unsafe {
        assert_eq!(p.read(), 0xef);
    }

    free_heap_pages(p, 1).expect("free");

    write_log(3, "init successful").unwrap();

    exit_current_thread(7000 + process_id.get() + 1);
}

/// The panic handler.
#[panic_handler]
pub fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    let _ = write_log(1, "panic!");
    exit_current_thread(1);
}
