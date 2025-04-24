//! Asynchronously wait for an exit notification.

use core::{
    pin::Pin,
    task::{Context, Poll},
};

use kernel_api::{
    ErrorCode, ExitReason, ProcessId, ThreadId, exit_notification_subscription,
    flags::ExitNotificationSubscriptionFlags,
};

use super::{EXECUTOR, PendingResponseState};

/// An id for a process or thread that can be watched for an exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchableId {
    /// A process ID.
    Process(ProcessId),
    /// A thread ID.
    Thread(ThreadId),
}

/// A future that resolves when an exit notification is received.
pub struct WatchExitFuture {
    id: WatchableId,
}

impl Future for WatchExitFuture {
    type Output = ExitReason;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut watched_exits = EXECUTOR
            .get()
            .expect("init task executor")
            .watched_exits
            .lock();

        match watched_exits.remove(&self.id) {
            Some(PendingResponseState::Ready(m)) => Poll::Ready(m),
            None | Some(PendingResponseState::Waiting(_)) => {
                watched_exits.insert(self.id, PendingResponseState::Waiting(cx.waker().clone()));
                Poll::Pending
            }
        }
    }
}

/// Subscribe the current process/thread to the exit notification sent when the `object` exits
/// using [`kernel_api::exit_notification_subscription`], and return a future that will resolve
/// when the notification is received.
///
/// # Errors
/// Returns an error if the `exit_notification_subscription` system call fails.
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::cast_possible_truncation)]
pub fn watch_exit(object: WatchableId) -> Result<WatchExitFuture, ErrorCode> {
    let (flags, id) = match object {
        WatchableId::Process(id) => (ExitNotificationSubscriptionFlags::PROCESS, id.get()),
        WatchableId::Thread(id) => (ExitNotificationSubscriptionFlags::THREAD, id.get()),
    };
    exit_notification_subscription(flags, id, EXECUTOR.get().unwrap().msg_queue)?;
    Ok(WatchExitFuture { id: object })
}
