//! Async API for sending RPC requests and awaiting their responses.
use core::{
    pin::Pin,
    task::{Context, Poll, Waker},
};

use kernel_api::{ErrorCode, Message, ProcessId, SharedBufferCreateInfo, ThreadId, send};

use crate::rpc::MessageHeader;

// TODO: we need a way to await the death of a process/thread ?!

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
/// received. The bytes in `msg` must start with a [`MessageHeader`]. Also, the `correlation_id`
/// must be unique.
pub fn send_request(
    dst_process_id: ProcessId,
    dst_thread_id: Option<ThreadId>,
    msg: &[u8],
    buffers: &[SharedBufferCreateInfo],
) -> Result<impl Future<Output = Message>, ErrorCode> {
    let hdr: &MessageHeader = bytemuck::from_bytes(&msg[0..core::mem::size_of::<MessageHeader>()]);
    let id = hdr.correlation_id();
    // TODO: assert message is request?
    send(dst_process_id, dst_thread_id, msg, buffers)?;
    Ok(ResponseFuture { id })
}
