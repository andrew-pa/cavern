//! Async task executor that runs the poll and receive loops.
use alloc::{boxed::Box, sync::Arc, task::Wake};
use bytemuck::from_bytes;
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::AtomicU64,
    task::{Context, Poll, Waker},
};
use crossbeam::queue::ArrayQueue;
use kernel_api::{
    EXIT_NOTIFICATION_TAG, ErrorCode, ExitMessage, ExitReason, Message, ProcessId, QueueId,
    ThreadId,
    flags::{FreeMessageFlags, ReceiveFlags},
    receive,
};
use spin::Mutex;

use hashbrown::HashMap;

use crate::rpc::{MessageHeader, MessageType, Service};

use super::{PendingResponseState, watch_exit::WatchableId};

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
        self.wake_task();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_task();
    }
}

pub struct Executor {
    /// The ID for the system message queue that this executor is listening on.
    pub msg_queue: QueueId,
    ready_queue: ReadyTaskQueue,
    new_task_queue: NewTaskQueue,
    next_task_id: Arc<AtomicU64>,
    // TODO: we could use a queue for this and reduce locking like the ready_queue, maybe?
    pub(super) pending_responses: Mutex<HashMap<u32, PendingResponseState<Message>>>,
    pub(super) watched_exits: Mutex<HashMap<WatchableId, PendingResponseState<ExitReason>>>,
}

impl Executor {
    pub fn new(msg_queue: QueueId) -> Self {
        Self {
            msg_queue,
            ready_queue: Arc::new(ArrayQueue::new(128)),
            new_task_queue: Arc::new(ArrayQueue::new(32)),
            next_task_id: Arc::new(AtomicU64::new(1)),
            pending_responses: Mutex::default(),
            watched_exits: Mutex::default(),
        }
    }

    pub fn spawn(&self, task: Box<dyn Future<Output = ()> + Send>) {
        let task_id = self
            .next_task_id
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        #[allow(clippy::match_wild_err_arm)]
        match self.new_task_queue.push((task_id, task.into())) {
            Ok(()) => (),
            Err(_) => panic!("new task queue overflow"),
        }
    }

    fn process_exit_notification(&self, msg: &Message) {
        let e = from_bytes::<ExitMessage>(msg.payload());
        assert_eq!(e.tag, EXIT_NOTIFICATION_TAG);
        let wi = match e.source {
            kernel_api::ExitSource::Thread => WatchableId::Thread(ThreadId::new(e.id).unwrap()),
            kernel_api::ExitSource::Process => WatchableId::Process(ProcessId::new(e.id).unwrap()),
        };
        let mut we = self.watched_exits.lock();
        if let Some(p) = we.get_mut(&wi) {
            p.become_ready(e.reason);
        } else {
            we.insert(wi, PendingResponseState::Ready(e.reason));
        }
    }

    fn process_message(&self, service: &impl Service, msg: Message) {
        let hdr: &MessageHeader =
            bytemuck::from_bytes(&msg.payload()[0..core::mem::size_of::<MessageHeader>()]);

        match hdr.msg_type() {
            Some(MessageType::Request | MessageType::Notification) => {
                self.spawn(Box::new(service.handle_message(msg)));
            }
            Some(MessageType::Response) => {
                let mut pr = self.pending_responses.lock();
                if let Some(p) = pr.get_mut(&hdr.correlation_id) {
                    p.become_ready(msg);
                } else {
                    pr.insert(hdr.correlation_id, PendingResponseState::Ready(msg));
                }
            }
            None if hdr.mtype == EXIT_NOTIFICATION_TAG => {
                self.process_exit_notification(&msg);
            }
            None => {
                // ignore unknown messages
                msg.free(FreeMessageFlags::FREE_BUFFERS);
            }
        }
    }

    fn check_for_messages(&self, service: &impl Service, block: bool) {
        let msg = receive(
            if block {
                ReceiveFlags::empty()
            } else {
                ReceiveFlags::NONBLOCKING
            },
            self.msg_queue,
        );
        match msg {
            Ok(m) => self.process_message(service, m),
            Err(ErrorCode::WouldBlock) if !block => {}
            Err(e) => panic!("failed to receive message: {e}"),
        }
    }

    /// Run the task executor forever. This is intended to be the effective entry point for the executor thread.
    pub fn run(&self, service: &impl Service) -> ! {
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

            self.check_for_messages(service, self.ready_queue.is_empty());

            // find and poll all ready tasks
            while let Some(task_id) = self.ready_queue.pop() {
                let Some(task) = tasks.get_mut(&task_id) else {
                    continue;
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
}
