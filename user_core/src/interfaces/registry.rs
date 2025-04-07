//! Registry service interface definitions.

use alloc::vec::Vec;
use bytemuck::{Contiguous, bytes_of, from_bytes};
use kernel_api::{Message, ProcessId, ThreadId};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt as _, Snafu};

use crate::{
    rpc::{MessageHeader, MessageType, ResponseType},
    tasks::send_request,
};

use super::{Error as RpcError, SendSnafu};

/// Op-codes for requests to the registry.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Contiguous)]
#[repr(u32)]
#[allow(missing_docs)]
pub enum OpCode {
    RegisterProvider = 1,
    UnregisterProvider,
    LookupResource,
}

/// A registry path that names a particular resource or resource provider.
pub type Path = str;

/// Error codes (response op-codes) for errors specific to the registry service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// The resource path was not found in the registry.
    NotFound = ResponseType::MAX_VALUE + 1,
    /// Unregister requested from a thread that was not registered
    NotRegistered,
}

unsafe impl Contiguous for ErrorCode {
    type Int = u32;
    const MIN_VALUE: Self::Int = ResponseType::MAX_VALUE + 1;
    const MAX_VALUE: Self::Int = ResponseType::MAX_VALUE + 2;
}

/// Errors that can happen making RPC calls to a registry.
#[derive(Debug, Snafu)]
pub enum Error {
    /// Error occurred due to the RPC protocol
    Rpc {
        /// The underlying error.
        source: RpcError,
    },
    /// The resource path was not found in the registry.
    NotFound,
    /// Unregister requested from a thread that was not registered
    NotRegistered,
    /// Error occurred deserializing response from service.
    Deserialize {
        /// The underlying error.
        source: postcard::Error,
    },
}

/// Result of looking up a resource in the registry.
#[derive(Debug, Clone)]
pub struct LookupResult<'a> {
    /// The relative path of the resource with respect to the root of the provider.
    pub rel_path: &'a Path,
    /// The provider process ID that provides this resource.
    pub provider_pid: ProcessId,
    /// The provider thread ID that provides this resource.
    pub provider_tid: ThreadId,
}

/// Response body of looking up a resource in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupResponseBody {
    /// The byte index into the input path that indicates the start of the relative path of the resource with respect to the root of the provider.
    pub rel_path_split_index: usize,
    /// The provider process ID that provides this resource.
    pub provider_pid: ProcessId,
    /// The provider thread ID that provides this resource.
    pub provider_tid: ThreadId,
}

/// A client for interacting with a registry service via RPC.
pub struct RegistryClient {
    pid: ProcessId,
    tid: Option<ThreadId>,
}

impl RegistryClient {
    /// Create a new client, connecting to the server at `pid`/`tid`.
    pub fn new(pid: ProcessId, tid: Option<ThreadId>) -> RegistryClient {
        Self { pid, tid }
    }

    fn encode_path_msg(&self, op: OpCode, path: &Path) -> Vec<u8> {
        let header = MessageHeader::new(MessageType::Request, op);
        let mut msg = Vec::with_capacity(core::mem::size_of::<MessageHeader>() + path.len());
        msg.extend_from_slice(bytes_of(&header));
        msg.extend_from_slice(path.as_bytes());
        msg
    }

    fn check_response<'a>(&self, response: &'a Message) -> Result<&'a [u8], Error> {
        let response_header = from_bytes::<MessageHeader>(
            &response.payload()[0..core::mem::size_of::<MessageHeader>()],
        );
        match ResponseType::from_integer(response_header.op_code()) {
            Some(ResponseType::Success) => {
                Ok(&response.payload()[core::mem::size_of::<MessageHeader>()..])
            }
            Some(ResponseType::InternalError) => Err(Error::Rpc {
                source: RpcError::Internal,
            }),
            Some(ResponseType::InvalidPayloadFormat) => Err(Error::Rpc {
                source: RpcError::InvalidPayloadFormat,
            }),
            // we should always get the op-code correct
            Some(ResponseType::UnknownOpcode) => {
                panic!("received unexpected response for register_provider: {response_header:?}")
            }
            None => match ErrorCode::from_integer(response_header.op_code()) {
                Some(ErrorCode::NotFound) => Err(Error::NotFound),
                Some(ErrorCode::NotRegistered) => Err(Error::NotRegistered),
                _ => panic!(
                    "received unexpected response for register_provider: {response_header:?}"
                ),
            },
        }
    }

    /// Register this process/thread as a resource provider with the registry.
    pub async fn register_provider(&self, root: &Path) -> Result<(), Error> {
        let msg = self.encode_path_msg(OpCode::RegisterProvider, root);
        let response = send_request(self.pid, self.tid, &msg, &[])
            .context(SendSnafu)
            .context(RpcSnafu)?
            .await;
        self.check_response(&response).map(|_| ())
    }

    /// Unregister this process/thread as a resource provider with the registry.
    pub async fn unregister_provider(&self) -> Result<(), Error> {
        let header = MessageHeader::new(MessageType::Request, OpCode::UnregisterProvider);
        let response = send_request(self.pid, self.tid, bytes_of(&header), &[])
            .context(SendSnafu)
            .context(RpcSnafu)?
            .await;
        self.check_response(&response).map(|_| ())
    }

    /// Lookup a resource's provider given its path.
    pub async fn lookup<'p>(&self, path: &'p Path) -> Result<LookupResult<'p>, Error> {
        let msg = self.encode_path_msg(OpCode::LookupResource, path);
        let response = send_request(self.pid, self.tid, &msg, &[])
            .context(SendSnafu)
            .context(RpcSnafu)?
            .await;
        let payload = self.check_response(&response)?;
        let r: LookupResponseBody = postcard::from_bytes(payload).context(DeserializeSnafu)?;
        Ok(LookupResult {
            rel_path: path.split_at(r.rel_path_split_index).1,
            provider_pid: r.provider_pid,
            provider_tid: r.provider_tid,
        })
    }
}
