//! Threads
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::sync::Arc;
use bytemuck::Contiguous;
use spin::Mutex;

use crate::memory::VirtualAddress;

use super::Process;

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
    Blocked,
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
