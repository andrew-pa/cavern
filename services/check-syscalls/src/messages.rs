//! Integration tests for message queues, sending and shared buffers.
#![allow(clippy::cast_possible_truncation)]

use alloc::boxed::Box;
use alloc::vec;

use kernel_api::{
    ErrorCode, QueueId, SharedBufferCreateInfo, create_message_queue,
    flags::{FreeMessageFlags, ReceiveFlags, SharedBufferFlags},
    free_message_queue, free_shared_buffers, receive, send, transfer_from_shared_buffer,
    transfer_to_shared_buffer,
};

use crate::Testable;

/// --- Message queue tests ---
fn queue_create_and_free() {
    let qid = create_message_queue().expect("create failed");
    assert!(qid.get() > 0);
    free_message_queue(qid).expect("free failed");
}

fn queue_double_free() {
    let qid = create_message_queue().expect("create failed");
    free_message_queue(qid).expect("first free failed");
    match free_message_queue(qid) {
        Err(ErrorCode::NotFound) => {}
        other => panic!("expected NotFound, got {:?}", other),
    }
}

fn queue_free_unknown() {
    let qid = QueueId::new(0xbeef_u32).unwrap();
    match free_message_queue(qid) {
        Err(ErrorCode::NotFound) => {}
        other => panic!("expected NotFound, got {:?}", other),
    }
}

/// --- Send/receive tests ---
fn send_and_receive_simple() {
    let qid = create_message_queue().expect("create queue failed");
    let msg = [1u8, 2, 3, 4];
    send(qid, &msg, &[]).expect("send failed");
    let m = receive(ReceiveFlags::empty(), qid).expect("receive failed");
    assert_eq!(m.header().num_buffers, 0);
    assert_eq!(m.payload(), msg.as_slice());
    m.free(FreeMessageFlags::empty());
    free_message_queue(qid).expect("free queue failed");
}

fn send_to_unknown_queue() {
    let qid = QueueId::new(0xdead_u32).unwrap();
    let msg = [9u8];
    match send(qid, &msg, &[]) {
        Err(ErrorCode::NotFound) => {}
        other => panic!("expected NotFound, got {:?}", other),
    }
}

fn send_zero_length_message() {
    let qid = create_message_queue().expect("create queue failed");
    match send(qid, &[], &[]) {
        Err(ErrorCode::InvalidLength) => {}
        other => panic!("expected InvalidLength, got {:?}", other),
    }
    free_message_queue(qid).expect("free queue failed");
}

fn send_receive_multiple_messages() {
    let qid = create_message_queue().expect("create queue failed");
    let messages: [&[u8]; 3] = [b"one", b"two", b"three"];

    for msg in &messages {
        send(qid, msg, &[]).expect("send failed");
    }

    for expected in &messages {
        let m = receive(ReceiveFlags::empty(), qid).expect("receive failed");
        assert_eq!(m.payload(), *expected);
        m.free(FreeMessageFlags::empty());
    }

    if let Err(ErrorCode::WouldBlock) = receive(ReceiveFlags::NONBLOCKING, qid) {
    } else {
        panic!("queue should be empty");
    }

    free_message_queue(qid).expect("free queue failed");
}

fn receive_nonblocking_empty() {
    let qid = create_message_queue().expect("create queue failed");
    if let Err(ErrorCode::WouldBlock) = receive(ReceiveFlags::NONBLOCKING, qid) {
    } else {
        panic!("expected WouldBlock");
    }
    free_message_queue(qid).expect("free queue failed");
}

/// --- Shared buffer tests ---
fn shared_buffer_roundtrip() {
    let qid = create_message_queue().expect("create queue failed");

    let mut backing = Box::new(*b"hello world");
    let sb = SharedBufferCreateInfo {
        base_address: backing.as_mut_ptr(),
        length: backing.len(),
        flags: SharedBufferFlags::READ | SharedBufferFlags::WRITE,
    };

    send(qid, &[], &[sb]).expect("send failed");
    let msg = receive(ReceiveFlags::empty(), qid).expect("receive failed");
    assert_eq!(msg.header().num_buffers, 1);
    let info = msg.buffers()[0].clone();
    assert_eq!(info.length, backing.len());
    let handle = info.buffer;
    msg.free(FreeMessageFlags::empty());

    let mut tmp = vec![0u8; backing.len()];
    transfer_from_shared_buffer(handle, 0, &mut tmp).expect("transfer from");
    assert_eq!(tmp.as_slice(), &*backing);

    let new = *b"goodbye!!!!"; // length 11
    transfer_to_shared_buffer(handle, 0, &new).expect("transfer to");
    assert_eq!(&backing[..new.len()], &new);

    free_shared_buffers(&[handle]).expect("free handle");
    match transfer_from_shared_buffer(handle, 0, &mut tmp) {
        Err(ErrorCode::NotFound) => {}
        other => panic!("expected NotFound after free, got {:?}", other),
    }

    free_message_queue(qid).expect("free queue failed");
}

fn shared_buffer_freed_with_message() {
    let qid = create_message_queue().expect("create queue failed");

    let mut backing = Box::new([0u8; 4]);
    backing.copy_from_slice(b"buf!");
    let sb = SharedBufferCreateInfo {
        base_address: backing.as_mut_ptr(),
        length: backing.len(),
        flags: SharedBufferFlags::READ,
    };

    send(qid, &[], &[sb]).expect("send failed");
    let msg = receive(ReceiveFlags::empty(), qid).expect("receive failed");
    let handle = msg.buffers()[0].buffer;
    msg.free(FreeMessageFlags::FREE_BUFFERS);

    match free_shared_buffers(&[handle]) {
        Err(ErrorCode::NotFound) => {}
        other => panic!("expected NotFound after free via message, got {:?}", other),
    }

    free_message_queue(qid).expect("free queue failed");
}

pub const TESTS: (&str, &[&dyn Testable]) = (
    "messages",
    &[
        &queue_create_and_free,
        &queue_double_free,
        &queue_free_unknown,
        &send_and_receive_simple,
        &send_to_unknown_queue,
        &send_zero_length_message,
        &send_receive_multiple_messages,
        &receive_nonblocking_empty,
        &shared_buffer_roundtrip,
        &shared_buffer_freed_with_message,
    ],
);
