//! Definitions for user space remote procedure call (RPC) protocol.
use core::sync::atomic::AtomicU32;

use bitfield::bitfield;
use bytemuck::{Contiguous, Pod, Zeroable};
use kernel_api::Message;

/// The type of an RPC message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Contiguous)]
#[repr(u8)]
pub enum MessageType {
    /// A request to run a procedure.
    Request,
    /// A request to run a procedure and then send the response elsewhere.
    ProxiedRequest,
    /// A response indicating the result of a [`Request`].
    Response,
    /// A notification that does not require a response.
    Notification,
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
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

bitfield! {
    /// The header for an RPC message.
    pub struct MessageHeader(u64);
    impl Debug;
    /// The type of this message.
    pub u8, into MessageType, msg_type, set_type: 3, 0;
    /// Message op-code. This is interpreted by the receiver, and should determine the exact procedure/method invoked for Requests/Notifications and the result code (ok/error) for Responses.
    pub u32, op_code, set_op_code: 31, 4;
    /// This value is generated by senders of Requests, and copied to the relevant Response that is sent back.
    /// This field is unspecified for Notifications and should be available for applications.
    pub u32, correlation_id, set_correlation_id: 64, 32;
}

impl Clone for MessageHeader {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for MessageHeader {}
unsafe impl Zeroable for MessageHeader {}
unsafe impl Pod for MessageHeader {}

static NEXT_CORRELATION_ID: AtomicU32 = AtomicU32::new(0);

/// Get the next unused correlation ID.
pub fn next_correlation_id() -> u32 {
    NEXT_CORRELATION_ID.fetch_add(1, core::sync::atomic::Ordering::AcqRel)
}

impl MessageHeader {
    /// Create a new message header with a fresh correlation ID.
    pub fn new(r#type: MessageType, op_code: impl Contiguous<Int = u32>) -> Self {
        let mut s = Self(0);
        s.set_type(r#type.into_integer());
        s.set_op_code(op_code.into_integer());
        s.set_correlation_id(next_correlation_id());
        s
    }
}

/// An RPC service.
pub trait Service {
    /// Handle an incoming request or notification message.
    /// The service must free the message and any attached buffers when it is finished with them.
    fn handle_message(&self, msg: Message) -> impl Future<Output = ()> + Send + 'static;
}
