//! Threads
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::{sync::Arc, vec::Vec};

use bytemuck::Contiguous;
use crossbeam::queue::SegQueue;
use kernel_api::{MessageHeader, ProcessId, SharedBufferInfo};
use log::{error, trace};
use spin::Mutex;

use crate::memory::{VirtualAddress, VirtualPointerMut};

use super::{PendingMessage, Process};

pub mod scheduler;

/// An unique ID for a thread.
pub type Id = crate::collections::Handle;
/// The largest possible thread ID in the system.
pub const MAX_THREAD_ID: Id = Id::new(0xffff).unwrap();

bitfield::bitfield! {
    /// The value of the SPSR (Saved Program Status) register.
    ///
    /// See `C5.2.18` of the architecture reference for more details.
    pub struct SavedProgramStatus(u64);
    impl Debug;
    /// Negative Condition Flag
    pub n, set_n: 31;
    /// Zero Condition Flag
    pub z, set_z: 30;
    /// Carry Condition Flag
    pub c, set_c: 29;
    /// Overflow Condition Flag
    pub v, set_v: 28;

    /// Tag Check Override
    pub tco, set_tco: 25;
    /// Data Independent Timing
    pub dit, set_dit: 24;
    /// User Access Override
    pub uao, set_uao: 23;
    /// Privileged Access Never
    pub pan, set_pan: 22;
    /// Software Step
    pub ss, set_ss: 21;
    /// Illegal Execution State
    pub il, set_il: 20;

    /// All IRQ/FIQ Interrupt Mask
    pub allint, set_allint: 13;
    /// Speculative Store Bypass
    pub ssbs, set_ssbs: 12;
    /// Branch Type Indicator
    pub btype, set_btype: 11, 10;

    /// Debug Exception Mask
    pub d, set_d: 9;
    /// System Error Exception Mask
    pub a, set_a: 8;
    /// IRQ Exception Mask
    pub i, set_i: 7;
    /// FIQ Exception Mask
    pub f, set_f: 6;

    /// Execution State and Exception Level
    pub el, set_el: 3, 2;

    /// Stack Pointer Selector
    pub sp, set_sp: 0;
}

impl SavedProgramStatus {
    /// Creates a suitable SPSR value for a thread running at EL0 (using the `SP_EL0` stack pointer).
    #[must_use]
    pub fn initial_for_el0() -> SavedProgramStatus {
        SavedProgramStatus(0)
    }

    /// Creates a suitable SPSR value for a thread running at EL1 on the kernel stack.
    #[must_use]
    pub fn initial_for_el1() -> SavedProgramStatus {
        let mut spsr = SavedProgramStatus(0);
        spsr.set_el(1);
        spsr.set_sp(true);
        spsr
    }
}

/// A stored version of the machine registers `x0..x31`.
#[derive(Default, Copy, Clone, Debug)]
#[repr(C)]
pub struct Registers {
    /// The values of the xN registers in order.
    pub x: [usize; 31],
}

/// Processor state of a thread.
#[derive(Debug)]
pub struct ProcessorState {
    /// The current program status register value.
    pub spsr: SavedProgramStatus,
    /// The current program counter.
    pub program_counter: VirtualAddress,
    /// The current stack pointer.
    pub stack_pointer: VirtualAddress,
    /// The current value of the `xN` registers.
    pub registers: Registers,
}

unsafe impl Send for ProcessorState {}

impl ProcessorState {
    /// Create a zeroed processor state that is valid for the idle thread.
    /// This is valid because the idle thread will always be saved before it is resumed, capturing
    /// the current execution state in the kernel.
    ///
    /// # Safety
    ///
    /// This should only be used for idle threads.
    #[must_use]
    pub unsafe fn new_for_idle_thread() -> Self {
        Self {
            spsr: SavedProgramStatus::initial_for_el1(),
            program_counter: VirtualAddress::from(0),
            stack_pointer: VirtualAddress::from(0),
            registers: Registers::default(),
        }
    }

    /// Create a new processor state suitable for a new user-space thread running in EL0.
    #[must_use]
    pub fn new_for_user_thread(
        entry_point: VirtualAddress,
        stack_pointer: VirtualAddress,
        user_data: usize,
    ) -> Self {
        let mut registers = Registers::default();
        registers.x[0] = user_data;
        Self {
            spsr: SavedProgramStatus::initial_for_el0(),
            program_counter: entry_point,
            stack_pointer,
            registers,
        }
    }
}

/// Execution state of a thread.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Contiguous)]
#[non_exhaustive]
pub enum State {
    /// Thread is currently executing or could currently execute.
    Running,
    /// Thread is blocked.
    WaitingForMessage,
    /// The thread has exited.
    Finished,
}

impl From<u8> for State {
    fn from(value: u8) -> Self {
        State::from_integer(value).expect("valid thread state")
    }
}

impl From<State> for u8 {
    fn from(value: State) -> Self {
        value.into_integer()
    }
}

bitfield::bitfield! {
    struct ThreadProperties(u64);
    impl Debug;
    u8, from into State, state, set_state: 8, 1;
}

impl ThreadProperties {
    fn new(state: State) -> Self {
        let mut s = Self(0);
        s.set_state(state);
        s
    }
}

/// A single thread of execution in a user-space process.
pub struct Thread {
    /// The unique id for this thread.
    pub id: Id,

    /// The process this thread is running in.
    pub parent: Option<Arc<Process>>,

    /// Thread status, etc
    properties: AtomicU64,

    /// The current processor state of the thread.
    pub processor_state: Mutex<ProcessorState>,

    /// (Stack base address, stack size in pages).
    pub stack: (VirtualAddress, usize),

    /// The queue of pointers to unreceived messages for this thread.
    pub inbox_queue: SegQueue<PendingMessage>,

    /// Threads/processes that will be notified when this thread exits.
    pub exit_subscribers: Mutex<Vec<(ProcessId, Option<Id>)>>,

    /// If the thread is [`State::WaitingForMessage`], then this contains the user space locations
    /// that need to be written when a message is received.
    pub pending_message_receive:
        Mutex<Option<(VirtualPointerMut<VirtualAddress>, VirtualPointerMut<usize>)>>,
}

impl Thread {
    /// Create a new Thread.
    #[must_use]
    pub fn new(
        id: Id,
        parent: Option<Arc<Process>>,
        initial_state: State,
        initial_processor_state: ProcessorState,
        stack: (VirtualAddress, usize),
    ) -> Thread {
        Self {
            id,
            parent,
            properties: AtomicU64::new(ThreadProperties::new(initial_state).0),
            processor_state: Mutex::new(initial_processor_state),
            stack,
            inbox_queue: SegQueue::new(),
            exit_subscribers: Mutex::default(),
            pending_message_receive: Mutex::default(),
        }
    }

    /// Load current thread state.
    pub fn state(&self) -> State {
        let props = ThreadProperties(self.properties.load(Ordering::Acquire));
        props.state()
    }

    /// Set the current thread state (atomically).
    pub fn set_state(&self, new_state: State) {
        let mut props = ThreadProperties(self.properties.load(Ordering::Relaxed));
        loop {
            let mut new_props = ThreadProperties(props.0);
            new_props.set_state(new_state);
            match self.properties.compare_exchange(
                props.0,
                new_props.0,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(p) => props = ThreadProperties(p),
            }
        }
    }

    /// Move the thread to the [`State::WaitingForMessage`] state.
    pub fn wait_for_message(
        &self,
        delivery_addr: VirtualPointerMut<VirtualAddress>,
        delivery_len: VirtualPointerMut<usize>,
    ) {
        debug_assert_eq!(self.state(), State::Running);
        trace!("thread #{} waiting for message", self.id);
        self.set_state(State::WaitingForMessage);
        let was_pending = self
            .pending_message_receive
            .lock()
            .replace((delivery_addr, delivery_len));
        assert!(was_pending.is_none(), "thread cannot wait for more than one message at a time, was waiting to deliver to {was_pending:?}");
    }

    /// Given that the thread is in the [`State::WaitingForMessage`] state, check to see if a
    /// message has arrived. If it has, the message is delivered, the thread transitions to the
    /// [`State::Running`] state, and true is returned. Otherwise the thread continues to wait and
    /// false is returned.
    pub fn check_resume(&self) -> bool {
        debug_assert_eq!(self.state(), State::WaitingForMessage);
        if let Some(msg) = self.inbox_queue.pop() {
            trace!("resuming thread #{} with message {msg:?}", self.id);
            let proc = self.parent.as_ref().unwrap();
            let pt = proc.page_tables.read();
            // write message header
            // SAFETY: this is fine because a message header can't span a page since messages are
            // 64-byte aligned and the header is less than 64 bytes.
            // TODO: this is still kinda sus
            let phy_msg_addr = pt
                .physical_address_of(msg.data_address)
                .expect("message data address is mapped in process page tables");
            unsafe {
                self.write_message_header(phy_msg_addr.into(), &msg);
            }
            // deliver message to user space
            let (user_delivery_address, user_delivery_length) =
                self.pending_message_receive.lock().take().unwrap();
            let Some(delivery_addr) = pt.physical_address_of(user_delivery_address.cast()) else {
                error!("process #{}, user space message address pointer was unmapped: {user_delivery_address:?}", proc.id);
                return false;
            };
            let Some(delivery_len) = pt.physical_address_of(user_delivery_length.cast()) else {
                error!("process #{}, user space message length pointer was unmapped: {user_delivery_length:?}", proc.id);
                return false;
            };
            let delivery_addr: *mut VirtualAddress = delivery_addr.cast().into();
            let delivery_len: *mut usize = delivery_len.cast().into();
            unsafe {
                delivery_addr.write(msg.data_address);
                delivery_len.write(msg.data_length);
            }
            // set up return value
            self.processor_state.lock().registers.x[0] = 0;
            self.set_state(State::Running);
            true
        } else {
            false
        }
    }

    /// Write the message header into the inbox, using `msg_base` as the base address of the message.
    unsafe fn write_message_header(&self, msg_base: VirtualAddress, msg: &PendingMessage) {
        let header: *mut MessageHeader = msg_base.cast::<MessageHeader>().as_ptr();
        header.write(MessageHeader {
            sender_pid: msg.sender_process_id,
            sender_tid: msg.sender_thread_id,
            num_buffers: msg.buffer_handles.len(),
        });

        let mut buffers: *mut SharedBufferInfo = msg_base
            .byte_add(size_of::<MessageHeader>())
            .cast()
            .as_ptr();
        let parent = self.parent.as_ref().unwrap();
        for buffer in msg.buffer_handles.iter().copied() {
            let b = parent
                .shared_buffers
                .get(buffer)
                .expect("pending message contains valid buffer handles");
            buffers.write(SharedBufferInfo {
                flags: b.flags,
                buffer,
                length: b.length,
            });
            buffers = buffers.add(1);
        }
    }

    /// Receive a message, returning the message's address in the process' virtual address space.
    /// The message header will be written as the first part of the message.
    /// The length is returned in bytes, and includes the header.
    ///
    /// # Safety
    /// This function is only safe to call if the current EL0 page tables are the process' page
    /// tables, because it directly writes the message header assuming that the address is mapped.
    /// This is an optimization and the restriction could be lifted.
    pub unsafe fn receive_message_immediately(&self) -> Option<(VirtualAddress, usize)> {
        let msg = self.inbox_queue.pop()?;

        trace!("thread #{} received message {msg:?}", self.id);

        self.write_message_header(msg.data_address, &msg);

        Some((msg.data_address, msg.data_length))
    }
}

/// Abstract scheduler policy
#[cfg_attr(test, mockall::automock)]
pub trait Scheduler: Sync {
    /// Add a new thread to the scheduler.
    fn spawn_new_thread(&self, thread: Arc<Thread>);

    /// Get the currently running thread.
    fn current_thread(&self) -> Arc<Thread>;

    /// Update the scheduler for a new time slice, potentially scheduling a new current thread.
    fn next_time_slice(&self);
}
