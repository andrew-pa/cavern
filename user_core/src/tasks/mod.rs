//! Async/await support for user space.
//! This includes a task executor implementation and an async API for sending RPC calls.
mod executor;
mod msg;
mod watch_exit;

use core::task::Waker;

use alloc::boxed::Box;
use executor::Executor;
use kernel_api::spawn_thread;
use spin::once::Once;

use crate::rpc::Service;

pub use msg::{ResponseFuture, send_request};
pub use watch_exit::{WatchExitFuture, WatchableId, watch_exit};

/// The global task executor instance.
pub static EXECUTOR: Once<Executor> = Once::new();

/// Spawn a future on the global executor.
pub fn spawn(f: impl Future<Output = ()> + Send + 'static) {
    EXECUTOR
        .get()
        .expect("task executor initialized")
        .spawn(Box::new(f));
}

fn task_thread_entry(_: usize) -> ! {
    EXECUTOR
        .get()
        .expect("executor initialized")
        .task_poll_loop()
}

/// Run the task executor with a root task and a service for handling RPC requests.
///
/// The `service` will listen as the current thread, which is assumed to be the designated receiver.
pub fn run(service: impl Service, root: impl Future<Output = ()> + Send + 'static) -> ! {
    let exec = EXECUTOR.call_once(Executor::default);
    exec.spawn(Box::new(root));
    spawn_thread(&kernel_api::ThreadCreateInfo {
        entry: task_thread_entry,
        stack_size: 1024,
        user_data: 0,
    })
    .expect("spawn task polling thread");
    // TODO: if a service wants to spawn two services running on two different threads, then the second
    // service thread needs to call `exec.designated_receiver_message_loop()` with that new service.
    // Otherwise receiving a request on a worker thread drops the message.
    exec.designated_receiver_message_loop(service)
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
            _ => panic!("received message twice for same id"),
        }
    }
}
