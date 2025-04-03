//! Async API for sending RPC requests and awaiting their responses.
use core::{
    pin::Pin,
    task::{Context, Poll, Waker},
};

use kernel_api::{ErrorCode, Message, ProcessId, SharedBufferCreateInfo, ThreadId, send};

use crate::rpc::MessageHeader;

use super::EXECUTOR;

/// The state of a [`ResponseFuture`] as it awaits a response.
pub(super) enum PendingResponseState {
    /// The future has been polled but we haven't received anything yet.
    Waiting(Waker),
    /// We have Received a message but haven't passed it back to the caller yet.
    Ready(Message),
}

unsafe impl Sync for PendingResponseState {}

impl PendingResponseState {
    pub fn become_ready(&mut self, msg: Message) {
        match core::mem::replace(self, Self::Ready(msg)) {
            Self::Waiting(w) => w.wake(),
            _ => panic!("received message twice for same id"),
        }
    }
}

/// A future representing a response that we are waiting to receive.
pub struct ResponseFuture {
    id: u32,
}

impl Future for ResponseFuture {
    type Output = Message;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut pr = EXECUTOR
            .get()
            .expect("init task executor")
            .pending_responses
            .lock();

        match pr.remove(&self.id) {
            Some(PendingResponseState::Ready(m)) => Poll::Ready(m),
            None | Some(PendingResponseState::Waiting(_)) => {
                pr.insert(self.id, PendingResponseState::Waiting(cx.waker().clone()));
                Poll::Pending
            }
        }
    }
}

/// Send an RPC request to the destination, returning a future that resolves when the response is
/// received.
///
/// To be function correct, `header` must be a slice into `full_msg`, or in other words the header must be
/// included in `full_msg` at the beginning.
pub fn send_request<'m>(
    dst_process_id: ProcessId,
    dst_thread_id: Option<ThreadId>,
    full_msg: &'m [u8],
    header: &'m MessageHeader,
    buffers: &[SharedBufferCreateInfo],
) -> Result<impl Future<Output = Message>, ErrorCode> {
    // TODO: assert message is request? assert that header is in full_msg?
    send(dst_process_id, dst_thread_id, full_msg, buffers)?;
    Ok(ResponseFuture {
        id: header.correlation_id(),
    })
}
