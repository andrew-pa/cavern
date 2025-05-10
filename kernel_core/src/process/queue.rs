//! User space message queues.

use core::sync::atomic::AtomicBool;

use alloc::sync::{Arc, Weak};
use crossbeam::queue::SegQueue;
use log::trace;
use snafu::OptionExt;

use crate::{memory::VirtualAddress, process::MissingSnafu};

use super::{ManagerError, Process, SharedBuffer};

/// The unique id for a message queue.
pub type Id = crate::collections::Handle;
/// The largest possible queue ID in the system.
pub const MAX_QUEUE_ID: Id = Id::new(0xffff).unwrap();

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
    pub owner: Weak<Process>,

    /// Has the queue already been freed?
    pub dead: AtomicBool,

    /// The queue of pointers to unreceived messages in the inbox.
    pub(super) pending: SegQueue<PendingMessage>,
}

impl MessageQueue {
    /// Create a new message queue object.
    pub fn new(id: Id, owner: &Arc<Process>) -> Self {
        MessageQueue {
            id,
            owner: Arc::downgrade(owner),
            pending: SegQueue::new(),
            dead: AtomicBool::new(false),
        }
    }

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
        let msg = self
            .owner
            .upgrade()
            .context(MissingSnafu {
                cause: "queue owner process already dead",
            })?
            .deliver_message(message, buffers)?;
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
    fn create_queue(&self, owner: &Arc<Process>) -> Result<Arc<MessageQueue>, ManagerError>;

    /// Frees a message queue, which frees all messages currently in the queue and also wakes all
    /// threads waiting on the queue with an error.
    fn free_queue(&self, queue: &Arc<MessageQueue>);

    /// Get the message queue object associated with a queue ID.
    fn queue_for_id(&self, queue_id: Id) -> Option<Arc<MessageQueue>>;
}
