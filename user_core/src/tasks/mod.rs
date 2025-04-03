//! Async/await support for user space.
//! This includes a task executor implementation and an async API for sending RPC calls.
mod executor;
mod msg;

use executor::Executor;
use kernel_api::spawn_thread;
use spin::once::Once;

use crate::rpc::Service;

pub use msg::{ResponseFuture, send_request};

/// The global task executor instance.
pub static EXECUTOR: Once<Executor> = Once::new();

/// Spawn a future on the global executor.
pub fn spawn(f: impl Future<Output = ()> + Send + 'static) {
    EXECUTOR.get().expect("task executor initialized").spawn(f);
}

fn task_thread_entry(_: usize) -> ! {
    EXECUTOR
        .get()
        .expect("executor initialized")
        .task_poll_loop()
}

/// Run the task executor with a root task and a service for handling RPC requests.
pub fn run(service: impl Service, root: impl Future<Output = ()> + Send + 'static) -> ! {
    let exec = EXECUTOR.call_once(Executor::default);
    exec.spawn(root);
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
