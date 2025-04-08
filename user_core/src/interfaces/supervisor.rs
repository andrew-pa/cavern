//! Supervisor service interface definitions.

use core::num::NonZeroUsize;

use super::{Error as RpcError, registry::Path};
use alloc::vec::Vec;
use kernel_api::{ProcessId, ThreadId};
use serde::{Deserialize, Serialize};
use snafu::Snafu;

/// Errors that can happen making RPC calls to a supervisor.
#[derive(Debug, Snafu)]
pub enum Error {
    /// Error occurred due to the RPC protocol
    Rpc {
        /// The underlying error.
        source: RpcError,
    },
    /// Error occurred serializing/deserializing a request to or response from the service.
    Serde {
        /// The underlying error.
        source: postcard::Error,
    },
}

/// Exit policies that can be executed after the maximum number of restarts has been reached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TerminalExitPolicy {
    /// Ignore the exit.
    Ignore,
    /// The supervisor kills all other supervised processes and exits itself.
    Cascade,
}

/// Policy to execute when a supervised process exits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExitPolicy {
    /// Ignore the exit.
    Ignore,
    /// Restart the process.
    Restart {
        /// The maximum number of times to restart the process, or `None` to keep restarting it forever.
        /// If the maximum is reached, the terminal exit policy will be executed.
        max_attempts: Option<(usize, TerminalExitPolicy)>,
        /// Number of milliseconds to wait before spawning the next instance.
        delay_ms: usize,
    },
    /// The supervisor kills all other supervised processes and exits itself.
    Cascade,
}

/// A specification for spawning a process that will be supervised by this supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSpec<'a> {
    /// The path to the binary to spawn.
    #[serde(borrow)]
    pub bin_path: &'a Path,

    /// The exit policy for this process, or `None` to inherit the default policy.
    pub exit_policy: Option<ExitPolicy>,

    /// Initial message to send to the process after spawning it.
    pub init_parameter: Option<&'a [u8]>,
}

/// Initial configuration for a supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorConfig<'a> {
    /// The default exit policy for supervised processes.
    pub default_exit_policy: ExitPolicy,

    /// Children to spawn for this supervisor.
    #[serde(borrow)]
    pub children: Vec<ProcessSpec<'a>>,
}

/// A client for interacting with a registry service via RPC.
pub struct SupervisorClient {
    pid: ProcessId,
    tid: Option<ThreadId>,
}

impl SupervisorClient {
    /// Create a new client, connecting to the server at `pid`/`tid`.
    pub fn new(pid: ProcessId, tid: Option<ThreadId>) -> Self {
        Self { pid, tid }
    }

    /// Configure the supervisor directly with a configuration.
    pub async fn configure(&self, config: &SupervisorConfig<'_>) -> Result<(), Error> {
        todo!()
    }

    /// Instruct the supervisor to load and parse a configuration from a file.
    pub async fn configure_from_file(&self, config_path: &Path) -> Result<(), Error> {
        todo!()
    }

    /// Cause the supervisor to spawn and supervise a new process.
    pub async fn spawn(&self, req: &ProcessSpec<'_>) -> Result<ProcessId, Error> {
        todo!()
    }
}
