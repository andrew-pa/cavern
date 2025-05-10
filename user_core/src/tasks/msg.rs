//! Async API for sending RPC requests and awaiting their responses.
use core::{
    pin::Pin,
    task::{Context, Poll},
};

use bytemuck::Contiguous;
use kernel_api::{ErrorCode, Message, QueueId, SharedBufferCreateInfo, send};

use crate::rpc::{MessageHeader, MessageType};

use super::{EXECUTOR, PendingResponseState};

/// A future representing a response that we are waiting to receive.
pub struct ResponseFuture {
    id: u32,
}

impl Future for ResponseFuture {
    type Output = Message;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut pending_responses = EXECUTOR
            .get()
            .expect("init task executor")
            .pending_responses
            .lock();

        match pending_responses.remove(&self.id) {
            Some(PendingResponseState::Ready(m)) => Poll::Ready(m),
            None | Some(PendingResponseState::Waiting(_)) => {
                pending_responses
                    .insert(self.id, PendingResponseState::Waiting(cx.waker().clone()));
                Poll::Pending
            }
        }
    }
}

/// Send an RPC request to the destination, returning a future that resolves when the response is
/// received. The bytes in `msg` must start with a [`MessageHeader`]. Also, the `correlation_id`
/// must be unique.
///
/// # Errors
/// Returns an error if the `send` call fails.
///
/// # Panics
/// Panics if the task executor has not been initialized yet.
pub fn send_request(
    dst_queue: QueueId,
    msg: &[u8],
    buffers: &[SharedBufferCreateInfo],
) -> Result<ResponseFuture, ErrorCode> {
    let hdr: &MessageHeader = bytemuck::from_bytes(&msg[0..core::mem::size_of::<MessageHeader>()]);
    let id = hdr.correlation_id;
    debug_assert_eq!(hdr.mtype, MessageType::Request.into_integer());
    debug_assert_eq!(hdr.response_queue, Some(EXECUTOR.get().unwrap().msg_queue));
    send(dst_queue, msg, buffers)?;
    Ok(ResponseFuture { id })
}
