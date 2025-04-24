//! Async/await support for user space.
//! This includes a task executor implementation and an async API for sending RPC calls.
mod executor;
mod msg;
mod watch_exit;

use core::task::Waker;

use alloc::boxed::Box;
use executor::Executor;
use kernel_api::QueueId;
use spin::once::Once;

use crate::rpc::Service;

pub use msg::{ResponseFuture, send_request};
pub use watch_exit::{WatchExitFuture, WatchableId, watch_exit};

/// The global task executor instance.
pub static EXECUTOR: Once<Executor> = Once::new();

/// Spawn a future on the global executor.
///
/// # Panics
/// Panics if the executor has not yet been initialized by [`run`].
pub fn spawn(f: impl Future<Output = ()> + Send + 'static) {
    EXECUTOR
        .get()
        .expect("task executor initialized")
        .spawn(Box::new(f));
}

/// Run the task executor with a root task and a service for handling RPC requests.
///
/// The `service` will listen as the current thread, which is assumed to be the designated receiver.
///
/// # Panics
/// Panics if a second task thread cannot be spawned.
pub fn run(
    msg_queue: QueueId,
    service: &impl Service,
    root: impl Future<Output = ()> + Send + 'static,
) -> ! {
    let exec = EXECUTOR.call_once(|| Executor::new(msg_queue));
    exec.spawn(Box::new(root));
    exec.run(service)
}

/// The state of a future that is waiting to receive a value of type `T`.
enum PendingResponseState<T> {
    /// The future has been polled but we haven't received anything yet.
    Waiting(Waker),
    /// We have Received a message but haven't passed it back to the caller yet.
    Ready(T),
}

unsafe impl<T> Sync for PendingResponseState<T> {}

impl<T> PendingResponseState<T> {
    pub fn become_ready(&mut self, val: T) {
        match core::mem::replace(self, Self::Ready(val)) {
            Self::Waiting(w) => w.wake(),
            Self::Ready(_) => panic!("received message twice for same id"),
        }
    }
}
