//! Threads
use alloc::sync::Arc;
#[cfg(test)]
use mockall::automock;
use spin::Mutex;

use crate::memory::VirtualAddress;

pub mod scheduler;

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

    /// Creates a suitable SPSR value for a thread running at EL1 with its own stack using the
    /// `SP_EL0` stack pointer.
    #[must_use]
    pub fn initial_for_el1() -> SavedProgramStatus {
        let mut spsr = SavedProgramStatus(0);
        spsr.set_el(1);
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

/// Execution state of a thread.
pub struct ExecutionState {
    /// The current program status register value.
    pub spsr: SavedProgramStatus,
    /// The current program counter.
    pub program_counter: VirtualAddress,
    /// The current stack pointer.
    pub stack_pointer: VirtualAddress,
    /// The current value of the `xN` registers.
    pub registers: Registers,
}

/// A single thread of execution in a user-space process.
pub struct Thread {
    /// The current program state of the thread.
    pub execution_state: Mutex<ExecutionState>,
}

/// Abstract scheduler policy
#[cfg_attr(test, automock)]
pub trait Scheduler: Sync {
    /// Get the currently running thread.
    fn current_thread(&self) -> Arc<Thread>;

    /// Update the thread scheduler for a new time slice,
    /// potentially updating the currently running thread.
    fn next_time_slice(&self);
}
