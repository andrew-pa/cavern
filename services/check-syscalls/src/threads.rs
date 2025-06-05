//! Integration tests for the threading‑related system calls.
//!
//! These tests are modelled after the style used in `heap.rs` and
//! `read_env_value.rs`, but focus exclusively on:
//!   * `spawn_thread` success + exit notification delivery
//!   * invalid parameter combinations (`InvalidLength`, `InvalidPointer`, …)
//!   * impossible resource requests (`OutOfMemory`)
//!   * `exit_notification_subscription` error handling
#![allow(clippy::cast_possible_truncation)]

use alloc::boxed::Box;
use alloc::format;
use core::mem;
use core::sync::atomic::{AtomicUsize, Ordering};

use bytemuck::cast_slice;
use kernel_api::{
    ErrorCode, ExitMessage, ExitReasonTag, ExitSource, ThreadCreateInfo, create_message_queue,
    exit_current_thread,
    flags::{ExitNotificationSubscriptionFlags, FreeMessageFlags},
    free_message_queue, receive, spawn_thread,
};

/// ---
/// Test helpers
/// ---
/// Simple thread entry that immediately exits with the supplied code.
fn simple_thread_entry(code: usize) -> ! {
    // Give the log a quick hint so we can trace ordering if needed.
    // Ignore any errors; this is just a best‑effort hint before exiting.
    let _ = kernel_api::write_log(4, &format!("child thread exit with {code}"));
    exit_current_thread(code as u32);
}

/// Builds a minimal, valid [`ThreadCreateInfo`] used by multiple tests.
fn mk_thread_info(entry: fn(usize) -> !, stack_pages: usize) -> ThreadCreateInfo {
    ThreadCreateInfo {
        entry,
        stack_size: stack_pages,
        user_data: 0x2Au8 as usize, // chosen test exit‑code
        notify_on_exit: None,
    }
}

/// ---
/// Happy‑path: spawn, exit, and notification via dedicated queue
/// ---
fn test_spawn_and_exit_notification() {
    // 1. Create a queue to receive the exit notification.
    let qid = create_message_queue().expect("queue creation failed");

    // 2. Prepare thread info – ask kernel to send exit notice to our queue.
    let info = ThreadCreateInfo {
        notify_on_exit: Some(qid),
        ..mk_thread_info(simple_thread_entry, 4)
    };

    // 3. Spawn and ensure we receive a valid thread id.
    let tid = spawn_thread(&info).expect("spawn_thread failed");
    assert!(tid.get() > 0);

    // 4. Block until the child exits and the kernel delivers the message.
    let msg = receive(kernel_api::flags::ReceiveFlags::empty(), qid).expect("receive failed");

    // 5. Validate message structure.
    assert_eq!(msg.header().num_buffers, 0, "no buffers expected");
    let payload = msg.payload();
    assert_eq!(
        payload.len(),
        mem::size_of::<ExitMessage>(),
        "plain exit message expected"
    );
    let exit_msg: &ExitMessage = cast_slice(payload).first().unwrap();

    // Tag + source + id + reason must match the spawned thread.
    assert_eq!(exit_msg.tag, kernel_api::EXIT_NOTIFICATION_TAG);
    assert_eq!(exit_msg.source, ExitSource::Thread);
    assert_eq!(exit_msg.id, tid.get());
    assert_eq!(exit_msg.reason.tag, ExitReasonTag::User);
    assert_eq!(exit_msg.reason.user_code, info.user_data as u32);

    // 6. Clean‑up.
    msg.free(FreeMessageFlags::empty());
    free_message_queue(qid).expect("free queue failed");
}

// How many increments each spawned thread performs.
// Keep this small so the test finishes in a few ms even on slow CI.
const CONCURRENT_ITERS: usize = 1000;
const CONCURRENT_THREADS: usize = 4;

/// Tiny worker that bumps the shared counter `CONCURRENT_ITERS` times.
fn concurrent_incrementer(counter_ptr: usize) -> ! {
    let counter = unsafe { &*(counter_ptr as *const AtomicUsize) };
    for _ in 0..CONCURRENT_ITERS {
        counter.fetch_add(1, Ordering::SeqCst);
    }
    exit_current_thread(0);
}

/// ---
/// Spawn several threads that all hammer a shared [`AtomicUsize`].
/// When every thread has exited, the counter must equal
/// `CONCURRENT_THREADS * CONCURRENT_ITERS`, proving that
///   * every thread really ran (concurrency/scheduling),
///   * they all wrote to **the same** address space (shared memory).
/// ---
fn test_threads_shared_address_space() {
    // 1. Allocate the counter on the heap so every thread sees the same address.
    let counter_ptr = Box::into_raw(Box::new(AtomicUsize::new(0)));

    // 2. Queue to collect exit notifications from the children.
    let qid = create_message_queue().expect("queue creation failed");

    // 3. Spawn the worker threads.
    for _ in 0..CONCURRENT_THREADS {
        let info = ThreadCreateInfo {
            entry: concurrent_incrementer,
            stack_size: 4,                   // four pages is plenty for a tight loop
            user_data: counter_ptr as usize, // pass the counter address
            notify_on_exit: Some(qid),
        };
        spawn_thread(&info).expect("spawn_thread failed");
    }

    // 4. Wait for all children to finish.
    for _ in 0..CONCURRENT_THREADS {
        let msg = receive(kernel_api::flags::ReceiveFlags::empty(), qid).expect("receive failed");
        msg.free(FreeMessageFlags::empty());
    }

    // 5. Verify the final counter value.
    let counter = unsafe { counter_ptr.cast_const().as_ref().unwrap() };
    let expected = CONCURRENT_THREADS * CONCURRENT_ITERS;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        expected,
        "shared counter mismatch: threads did not all run or did not share memory"
    );

    // 6. Clean‑up
    free_message_queue(qid).ok();
    unsafe { drop(Box::from_raw(counter_ptr)) }
}

/// ---
/// Invalid parameter: zero stack size ⇒ `InvalidLength`
/// ---
fn test_spawn_zero_stack() {
    let info = mk_thread_info(simple_thread_entry, 0);
    match spawn_thread(&info) {
        Err(ErrorCode::InvalidLength) => {}
        other => panic!("expected InvalidLength, got {:?}", other),
    }
}

/// ---
/// Invalid parameter: null entry pointer ⇒ `InvalidPointer`
/// ---
#[allow(clippy::transmute_null_to_fn, invalid_value)]
fn test_spawn_null_entry() {
    // SAFETY: we deliberately craft an invalid function pointer.
    let null_fn: fn(usize) -> ! = unsafe { mem::transmute::<usize, fn(usize) -> !>(0) };
    let info = mk_thread_info(null_fn, 4);
    match spawn_thread(&info) {
        Err(ErrorCode::InvalidPointer) => {}
        other => panic!("expected InvalidPointer, got {:?}", other),
    }
}

/// ---
/// Over‑large stack request ⇒ `OutOfMemory` *or* `InvalidLength`
/// ---
fn test_spawn_out_of_memory() {
    let info = mk_thread_info(simple_thread_entry, usize::MAX);
    match spawn_thread(&info) {
        Err(ErrorCode::OutOfMemory | ErrorCode::InvalidLength) => {}
        other => panic!("expected OutOfMemory/InvalidLength, got {:?}", other),
    }
}

/// ---
/// `exit_notification_subscription` bad flag combo ⇒ `InvalidFlags`
/// ---
fn test_exit_sub_invalid_flags() {
    let qid = create_message_queue().expect("queue creation failed");
    let flags =
        ExitNotificationSubscriptionFlags::PROCESS | ExitNotificationSubscriptionFlags::THREAD;
    match kernel_api::exit_notification_subscription(flags, 0, qid) {
        Err(ErrorCode::InvalidFlags) => {}
        other => panic!("expected InvalidFlags, got {:?}", other),
    }
    free_message_queue(qid).ok();
}

/// ---
/// Subscribe to a non‑existent thread id ⇒ `NotFound`
/// ---
fn test_exit_sub_unknown_thread() {
    let qid = create_message_queue().expect("queue creation failed");
    match kernel_api::exit_notification_subscription(
        ExitNotificationSubscriptionFlags::THREAD,
        0xEEDD_F00Du32,
        qid,
    ) {
        Err(ErrorCode::NotFound) => {}
        other => panic!("expected NotFound, got {:?}", other),
    }
    free_message_queue(qid).ok();
}

/// Public list consumed by `src/main.rs`
pub const TESTS: (&str, &[&dyn crate::Testable]) = (
    "threads",
    &[
        &test_spawn_and_exit_notification,
        &test_threads_shared_address_space,
        &test_spawn_zero_stack,
        &test_spawn_null_entry,
        &test_spawn_out_of_memory,
        &test_exit_sub_invalid_flags,
        &test_exit_sub_unknown_thread,
    ],
);
