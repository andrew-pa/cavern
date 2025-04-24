//! Registry service interface definitions.

use alloc::vec::Vec;
use bytemuck::{Contiguous, bytes_of, from_bytes};
use kernel_api::{Message, ProcessId, QueueId, ThreadId};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt as _, Snafu};

use crate::{
    rpc::{MessageHeader, MessageType, ResponseType},
    tasks::{EXECUTOR, send_request},
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
    /// Error occurred serializing/deserializing a request to or response from the service.
    Serde {
        /// The underlying error.
        source: postcard::Error,
    },
}

/// Request body for registering a provider with the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterProviderRequest<'a> {
    /// The provider thread ID in the requesting process that provides this resource.
    pub provider_tid: ThreadId,
    #[serde(borrow)]
    root: &'a Path,
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
    qid: QueueId,
}

impl RegistryClient {
    /// Create a new client, connecting to the server at `pid`/`tid`.
    #[must_use]
    pub fn new(registry_queue: QueueId) -> Self {
        Self {
            qid: registry_queue,
        }
    }

    fn encode_path_msg(op: OpCode, path: &Path) -> Vec<u8> {
        let header = MessageHeader::request(op);
        let mut msg = Vec::with_capacity(core::mem::size_of::<MessageHeader>() + path.len());
        msg.extend_from_slice(bytes_of(&header));
        msg.extend_from_slice(path.as_bytes());
        msg
    }

    fn check_response(response: &Message) -> Result<&[u8], Error> {
        let response_header = from_bytes::<MessageHeader>(
            &response.payload()[0..core::mem::size_of::<MessageHeader>()],
        );
        match ResponseType::from_integer(response_header.opcode) {
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
            None => match ErrorCode::from_integer(response_header.opcode) {
                Some(ErrorCode::NotFound) => Err(Error::NotFound),
                Some(ErrorCode::NotRegistered) => Err(Error::NotRegistered),
                _ => panic!(
                    "received unexpected response for register_provider: {response_header:?}"
                ),
            },
        }
    }

    /// Register the thread as a resource provider with the registry.
    ///
    /// # Errors
    /// Returns an error if the RPC call fails or returns an error.
    pub async fn register_provider(
        &self,
        root: &Path,
        provider_tid: ThreadId,
    ) -> Result<(), Error> {
        let op = OpCode::RegisterProvider;
        let header = MessageHeader::request(op);
        let mut msg = Vec::new();
        msg.extend_from_slice(bytes_of(&header));
        let msg = postcard::to_extend(&RegisterProviderRequest { provider_tid, root }, msg)
            .context(SerdeSnafu)?;
        let response = send_request(self.qid, &msg, &[])
            .context(SendSnafu)
            .context(RpcSnafu)?
            .await;
        Self::check_response(&response).map(|_| ())
    }

    /// Unregister this process/thread as a resource provider with the registry.
    ///
    /// # Errors
    /// Returns an error if the RPC call fails or returns an error.
    pub async fn unregister_provider(&self) -> Result<(), Error> {
        let header = MessageHeader::request(OpCode::UnregisterProvider);
        let response = send_request(self.qid, bytes_of(&header), &[])
            .context(SendSnafu)
            .context(RpcSnafu)?
            .await;
        Self::check_response(&response).map(|_| ())
    }

    /// Lookup a resource's provider given its path.
    ///
    /// # Errors
    /// Returns an error if the RPC call fails or returns an error.
    pub async fn lookup<'p>(&self, path: &'p Path) -> Result<LookupResult<'p>, Error> {
        let msg = Self::encode_path_msg(OpCode::LookupResource, path);
        let response = send_request(self.qid, &msg, &[])
            .context(SendSnafu)
            .context(RpcSnafu)?
            .await;
        let payload = Self::check_response(&response)?;
        let r: LookupResponseBody = postcard::from_bytes(payload).context(SerdeSnafu)?;
        Ok(LookupResult {
            rel_path: path.split_at(r.rel_path_split_index).1,
            provider_pid: r.provider_pid,
            provider_tid: r.provider_tid,
        })
    }
}
