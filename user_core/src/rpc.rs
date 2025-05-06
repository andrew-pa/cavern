//! Definitions for user space remote procedure call (RPC) protocol.
use core::sync::atomic::AtomicU32;

use bytemuck::{Contiguous, Pod, Zeroable};
use kernel_api::{Message, QueueId};

use crate::tasks::EXECUTOR;

/// The type of an RPC message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Contiguous, Zeroable)]
#[repr(u32)]
pub enum MessageType {
    /// A request to run a procedure.
    Request,
    /// A response indicating the result of a [`Request`].
    Response,
    /// A notification that does not require a response.
    Notification,
    // `0xff` is reserved by the kernel for exit notifications but these notifications are not
    // actually RPC messages.
}

impl From<u32> for MessageType {
    fn from(value: u32) -> Self {
        Self::from_integer(value).expect("message type is known")
    }
}

/// Standard response types (the op-code in a Response message).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Contiguous)]
#[repr(u32)]
pub enum ResponseType {
    /// The request completed successfully, with any results passed in the response payload.
    Success = 0,
    /// The request op-code was unknown to the receiver.
    UnknownOpcode,
    /// The request's payload was in a format that the receiver could not interpret.
    InvalidPayloadFormat,
    /// An error internal to the receiver occurred, preventing the completion of the request.
    InternalError,
}

/// The header of an RPC message.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct MessageHeader {
    /// The type of this message, should be a [`MessageType`] value.
    pub mtype: u32,
    /// The opcode for this message, selecting the requested action or response success/error.
    pub opcode: u32,
    /// The correlation ID for this message.
    pub correlation_id: u32,
    /// The queue to send a response to, if any.
    pub response_queue: Option<QueueId>,
}

static NEXT_CORRELATION_ID: AtomicU32 = AtomicU32::new(0);

/// Get the next unused correlation ID.
pub fn next_correlation_id() -> u32 {
    NEXT_CORRELATION_ID.fetch_add(1, core::sync::atomic::Ordering::AcqRel)
}

impl MessageHeader {
    /// Create a new message header with a fresh correlation ID.
    pub fn new(
        mtype: MessageType,
        opcode: impl Contiguous<Int = u32>,
        response_queue: impl Into<Option<QueueId>>,
    ) -> Self {
        Self {
            mtype: mtype.into_integer(),
            opcode: opcode.into_integer(),
            correlation_id: next_correlation_id(),
            response_queue: response_queue.into(),
        }
    }

    /// Create a new message header for a request, expecting a response on the task executor's message queue.
    ///
    /// # Panics
    /// Panics if the task executor has not been initalized yet.
    pub fn request(opcode: impl Contiguous<Int = u32>) -> Self {
        Self::new(
            MessageType::Request,
            opcode,
            EXECUTOR.get().unwrap().msg_queue,
        )
    }

    /// The type of this message, or `None` if the type is unknown/invalid.
    #[must_use]
    pub fn msg_type(&self) -> Option<MessageType> {
        MessageType::from_integer(self.mtype)
    }
}

/// An RPC service.
pub trait Service {
    /// Handle an incoming request or notification message.
    /// The service must free the message and any attached buffers when it is finished with them.
    fn handle_message(&self, msg: Message) -> impl Future<Output = ()> + Send + 'static;
}
