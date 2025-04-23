//! User space message queues.

use alloc::sync::Arc;
use alloc::vec::Vec;
use crossbeam::queue::SegQueue;
use log::trace;

use crate::memory::VirtualAddress;

use super::{
    Id as ProcessId, Process, ManagerError, SharedBuffer, SharedBufferId, ThreadId,
};

/// The unique id for a message queue.
pub type Id = crate::collections::Handle;

/// A message that is waiting in a queue to be received.
#[derive(Debug)]
pub struct PendingMessage {
    /// The address of the message in the process' virtual address space.
    pub data_address: VirtualAddress,
    /// The length of the message in bytes.
    pub data_length: usize,
}

/// A message queue for messages sent to a process.
pub struct MessageQueue {
    /// The ID of this queue.
    pub id: Id,

    /// The process that created the queue. Only this process can receive messages.
    pub owner: Arc<Process>,

    /// The queue of pointers to unreceived messages in the inbox.
    pending: SegQueue<PendingMessage>,
}

impl MessageQueue {
    /// Send a message to this queue by delivering it to the owner mailbox and then enqueuing the
    /// message.
    ///
    /// # Errors
    /// Returns an error if the message could not be delivered, or something goes wrong with memory
    /// or page tables.
    pub fn send(
        &self,
        message: &[u8],
        buffers: impl ExactSizeIterator<Item = Arc<SharedBuffer>>,
    ) -> Result<(), ManagerError> {
        let msg = self.owner.deliver_message(message, buffers)?;
        trace!("enqueuing {msg:?} in queue #{}", self.id);
        self.pending.push(msg);
        Ok(())
    }

    /// Receive a message from the queue, if there is one pending.
    pub fn receive(&self) -> Option<PendingMessage> {
        self.pending.pop()
    }
}

/// An interface for managing message queues.
#[cfg_attr(test, mockall::automock)]
pub trait QueueManager {
    /// Create a new message queue.
    ///
    /// # Errors
    /// Returns an error if a new queue could not be created.
    fn create_queue(&self) -> Result<Arc<MessageQueue>, ManagerError>;

    /// Frees a message queue, which frees all messages currently in the queue and also wakes all
    /// threads waiting on the queue with an error.
    ///
    /// # Errors
    /// Returns an error if the queue could not be deleted.
    fn free_queue(&self, queue: &Arc<MessageQueue>) -> Result<(), ManagerError>;

    /// Get the message queue object associated with a queue ID.
    fn queue_for_id(&self, queue_id: Id) -> Option<Arc<MessageQueue>>;
}
