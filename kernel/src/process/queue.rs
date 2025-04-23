//! Message queue mechanisms

use kernel_core::{
    collections::HandleMap,
    process::{queue::MAX_QUEUE_ID, ManagerError, MessageQueue, MissingSnafu, OutOfHandlesSnafu},
};
use log::warn;

/// The system message queue manager.
pub struct SystemQueueManager {
    queues: HandleMap<MessageQueue>,
}

/// The system message queue manager instance.
pub static QUEUE_MANAGER: Once<SystemQueueManager> = Once::new();

pub fn init() {
    QUEUE_MANAGER.call_once(|| SystemQueueManager {
        queues: HandleMap::new(MAX_QUEUE_ID),
    })
}

impl QueueManager for SystemQueueManager {
    fn create_queue(&self, owner: Arc<Process>) -> Result<Arc<MessageQueue>, ManagerError> {
        let id = self
            .queues
            .preallocate_handle()
            .context(OutOfHandlesSnafu)?;
        let q = Arc::new(MessageQueue::new(id, owner));
        self.queues.insert_with_handle(id, q.clone());
        Ok(q)
    }

    fn free_queue(&self, queue: &Arc<MessageQueue>) -> Result<(), ManagerError> {
        // Remove the queue from the table. This will cause any future sends to fail.
        let q = self.queues.remove(queue.id).context(MissingSnafu {
            cause: "freeing queue not in table",
        })?;

        /// Make sure any waiting threads know that this queue is dead.
        q.dead.store(true);

        // Drain any remaining messages
        while let Some(m) = q.receive() {
            if Err(e) = q.owner.free_message(m.data_address, m.data_length) {
                warn!(
                    "failed to free message {m:?} while freeing queue #{}: {}",
                    q.id,
                    snafu::Report::from_error(e)
                );
            }
        }

        Ok(())
    }

    fn queue_for_id(&self, queue_id: Id) -> Option<Arc<MessageQueue>> {
        self.queues.get(queue_id)
    }
}
