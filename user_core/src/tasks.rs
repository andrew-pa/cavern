//! Async task executor and other async machinary.
use alloc::{boxed::Box, sync::Arc, task::Wake};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::AtomicU64,
    task::{Context, Poll, Waker},
};
use crossbeam::queue::ArrayQueue;
use kernel_api::{
    ErrorCode, Message, ProcessId, SharedBufferCreateInfo, ThreadId, flags::ReceiveFlags, receive,
    send, spawn_thread,
};
use spin::{Mutex, once::Once};

use hashbrown::HashMap;

use crate::rpc::{MessageHeader, MessageType, Service};

type TaskId = u64;
type Task = Pin<Box<dyn Future<Output = ()> + Send>>;
type ReadyTaskQueue = Arc<ArrayQueue<TaskId>>;
type NewTaskQueue = Arc<ArrayQueue<(TaskId, Task)>>;

struct TaskWaker {
    id: TaskId,
    ready_queue: ReadyTaskQueue,
}

impl TaskWaker {
    fn new_waker(id: TaskId, ready_queue: ReadyTaskQueue) -> Waker {
        Waker::from(Arc::new(TaskWaker { id, ready_queue }))
    }

    fn wake_task(&self) {
        self.ready_queue.push(self.id).expect("task queue overflow");
    }
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_task()
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_task()
    }
}

struct Executor {
    ready_queue: ReadyTaskQueue,
    new_task_queue: NewTaskQueue,
    next_task_id: Arc<AtomicU64>,
    // TODO: we could use a queue for this and reduce locking like the ready_queue, maybe?
    pending_responses: Mutex<HashMap<u32, PendingResponseState>>,
}

impl Default for Executor {
    fn default() -> Self {
        Self {
            ready_queue: Arc::new(ArrayQueue::new(128)),
            new_task_queue: Arc::new(ArrayQueue::new(32)),
            next_task_id: Arc::new(AtomicU64::new(1)),
            pending_responses: Mutex::default(),
        }
    }
}

impl Executor {
    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let task_id = self
            .next_task_id
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        match self.new_task_queue.push((task_id, Box::pin(task))) {
            Ok(()) => (),
            Err(_) => panic!("new task queue overflow"),
        }
    }

    fn wake_task_for_msg(&self, msg: Message) {
        let hdr: &MessageHeader =
            bytemuck::from_bytes(&msg.payload()[0..core::mem::size_of::<MessageHeader>()]);
        self.pending_responses
            .lock()
            .entry(hdr.correlation_id())
            .or_default()
            .ready(msg);
    }

    /// Run the task executor forever. This is intended to be the effective entry point for the executor thread.
    fn task_poll_loop(&self) -> ! {
        let mut tasks = HashMap::new();
        let mut waker_cache = HashMap::new();

        loop {
            // spawn any new tasks as ready to run
            while let Some((task_id, task)) = self.new_task_queue.pop() {
                tasks.insert(task_id, task);
                // make sure tasks are only in the ready queue after they have been added to the tasks map
                self.ready_queue
                    .push(task_id)
                    .expect("ready task queue overflow");
            }

            // check to see if this thread received any messages
            loop {
                match receive(ReceiveFlags::NONBLOCKING) {
                    Ok(msg) => self.wake_task_for_msg(msg),
                    Err(ErrorCode::WouldBlock) => break,
                    Err(e) => panic!("failed to receive message: {e}"),
                }
            }

            // find and poll all ready tasks
            while let Some(task_id) = self.ready_queue.pop() {
                let task = match tasks.get_mut(&task_id) {
                    Some(t) => t,
                    None => continue,
                };
                let waker = waker_cache
                    .entry(task_id)
                    .or_insert_with(|| TaskWaker::new_waker(task_id, self.ready_queue.clone()));
                let mut context = Context::from_waker(waker);
                match task.as_mut().poll(&mut context) {
                    Poll::Ready(()) => {
                        tasks.remove(&task_id);
                        waker_cache.remove(&task_id);
                    }
                    Poll::Pending => {}
                }
            }
        }
    }

    /// Run a receive only message loop to wake tasks waiting for responses and handle incoming requests.
    fn designated_receiver_message_loop(&self, service: impl Service) -> ! {
        loop {
            let msg = receive(ReceiveFlags::empty()).unwrap();
            todo!();
            self.wake_task_for_msg(msg);
        }
    }
}

static EXECUTOR: Once<Executor> = Once::new();

/// Spawn a future on the global executor.
pub fn spawn(f: impl Future<Output = ()> + Send + 'static) {
    EXECUTOR.get().expect("task executor initialized").spawn(f);
}

#[derive(Default)]
enum PendingResponseState {
    #[default]
    NeverPolled,
    Waiting(Waker),
    Ready(Message),
    Taken,
}

unsafe impl Sync for PendingResponseState {}

impl PendingResponseState {
    fn ready(&mut self, msg: Message) {
        match core::mem::replace(self, Self::Ready(msg)) {
            Self::Waiting(w) => w.wake(),
            // it is possible that we got a response *before* we got polled
            Self::NeverPolled => {}
            _ => panic!("received message twice for same id"),
        }
    }

    fn poll(&mut self, waker: &Waker) -> Poll<Message> {
        if matches!(self, Self::Ready(_)) {
            match core::mem::replace(self, Self::Taken) {
                Self::Ready(m) => Poll::Ready(m),
                _ => unreachable!(),
            }
        } else {
            assert!(
                !matches!(self, Self::Taken),
                "polled message already received"
            );
            *self = Self::Waiting(waker.clone());
            Poll::Pending
        }
    }
}

struct ResponseFuture {
    id: u32,
}

impl Future for ResponseFuture {
    type Output = Message;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        EXECUTOR
            .get()
            .expect("init task executor")
            .pending_responses
            .lock()
            .entry(self.id)
            .or_default()
            .poll(cx.waker())
    }
}

/// Send an RPC request to the destination, returning a future that resolves when the response is
/// received.
///
/// To be function correct, `header` must be a slice into `full_msg`, or in other words the header must be
/// included in `full_msg` at the beginning.
pub fn send_request<'m>(
    dst_process_id: ProcessId,
    dst_thread_id: Option<ThreadId>,
    full_msg: &'m [u8],
    header: &'m MessageHeader,
    buffers: &[SharedBufferCreateInfo],
) -> Result<impl Future<Output = Message>, ErrorCode> {
    // TODO: assert message is request? assert that header is in full_msg?
    send(dst_process_id, dst_thread_id, full_msg, buffers)?;
    Ok(ResponseFuture {
        id: header.correlation_id(),
    })
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
    exec.designated_receiver_message_loop(service)
}
