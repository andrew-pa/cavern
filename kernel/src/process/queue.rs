//! Message queue mechanisms

use alloc::sync::Arc;
use kernel_core::{
    collections::HandleMap,
    process::{
        queue::{QueueManager, MAX_QUEUE_ID},
        ManagerError, MessageQueue, MissingSnafu, OutOfHandlesSnafu, Process, QueueId,
    },
};
use log::warn;
use snafu::OptionExt;
use spin::Once;

/// The system message queue manager.
pub struct SystemQueueManager {
    queues: HandleMap<MessageQueue>,
}

/// The system message queue manager instance.
pub static QUEUE_MANAGER: Once<SystemQueueManager> = Once::new();

/// Initialize the message queue manager.
pub fn init() {
    QUEUE_MANAGER.call_once(|| SystemQueueManager {
        queues: HandleMap::new(MAX_QUEUE_ID),
    });
}

impl QueueManager for SystemQueueManager {
    fn create_queue(&self, owner: &Arc<Process>) -> Result<Arc<MessageQueue>, ManagerError> {
        let id = self
            .queues
            .preallocate_handle()
            .context(OutOfHandlesSnafu)?;
        let q = Arc::new(MessageQueue::new(id, owner));
        self.queues.insert_with_handle(id, q.clone());
        owner.owned_queues.lock().push(q.clone());
        Ok(q)
    }

    fn free_queue(&self, queue: &Arc<MessageQueue>) {
        // Remove the queue from the table. This will cause any future sends to fail.
        let queue = self
            .queues
            .remove(queue.id)
            .expect("freed queue is in table");

        // Make sure any waiting threads know that this queue is dead.
        queue
            .dead
            .store(true, core::sync::atomic::Ordering::Release);

        // TODO: might be good to unsubscribe from any processes/threads?

        // Drain any remaining messages
        if let Some(owner) = queue.owner.upgrade() {
            owner.owned_queues.lock().retain(|qu| qu.id != queue.id);
            while let Some(m) = queue.receive() {
                if let Err(e) = owner.free_message(m.data_address, m.data_length) {
                    warn!(
                        "failed to free message {m:?} while freeing queue #{}: {}",
                        queue.id,
                        snafu::Report::from_error(e)
                    );
                }
            }
        }
    }

    fn queue_for_id(&self, queue_id: QueueId) -> Option<Arc<MessageQueue>> {
        self.queues.get(queue_id)
    }
}
