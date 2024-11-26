//! Thread switching mechanism.

use kernel_core::{
    memory::VirtualAddress,
    process::thread::{scheduler::RoundRobinScheduler, Registers, SavedProgramStatus, Scheduler},
};
use spin::once::Once;

pub type PlatformScheduler = RoundRobinScheduler;

pub static SCHEDULER: Once<PlatformScheduler> = Once::new();

pub fn init() {
    SCHEDULER.call_once(|| PlatformScheduler::new());
}

/// Read the current value of the `SPSR_EL1` register.
pub fn read_saved_program_status() -> SavedProgramStatus {
    let mut v: u64;
    unsafe {
        core::arch::asm!("mrs {v}, SPSR_EL1", v = out(reg) v);
    }
    SavedProgramStatus(v)
}

/// Write to the `SPSR_EL1` register.
///
/// # Safety
/// It is up to the caller to ensure that the `SavedProgramStatus` value is correct.
pub unsafe fn write_saved_program_status(spsr: &SavedProgramStatus) {
    core::arch::asm!("msr SPSR_EL1, {v}", v = in(reg) spsr.0);
}

/// Read the value of the program counter when the exception occured.
pub fn read_exception_link_reg() -> VirtualAddress {
    let mut v: usize;
    unsafe {
        core::arch::asm!("mrs {v}, ELR_EL1", v = out(reg) v);
    }
    v.into()
}

/// Write the value that the program counter will assume when the exception handler is finished.
///
/// # Safety
/// It is up to the caller to ensure that the address is valid to store as the program counter.
pub unsafe fn write_exception_link_reg(addr: VirtualAddress) {
    core::arch::asm!("msr ELR_EL1, {v}", v = in(reg) usize::from(addr));
}

/// Reads the stack pointer for exception level `el`.
pub fn read_stack_pointer(el: u8) -> VirtualAddress {
    let mut v: usize;
    unsafe {
        match el {
            0 => core::arch::asm!("mrs {v}, SP_EL0", v = out(reg) v),
            1 => core::arch::asm!("mrs {v}, SP_EL1", v = out(reg) v),
            2 => core::arch::asm!("mrs {v}, SP_EL2", v = out(reg) v),
            // 3 => core::arch::asm!("mrs {v}, SP_EL3", v = out(reg) v),
            _ => panic!("invalid exception level {el}"),
        }
    }
    v.into()
}

/// Writes the stack pointer for exception level `el`.
///
/// # Safety
/// It is up to the caller to ensure that the pointer is valid to be stack pointer (i.e. the memory
/// is allocated and mapped correctly). It is also up to the caller to pass a value for `el` that
/// is valid considering the current value of `el`.
pub unsafe fn write_stack_pointer(el: u8, sp: VirtualAddress) {
    let addr = usize::from(sp);
    match el {
        0 => core::arch::asm!("msr SP_EL0, {v}", v = in(reg) addr),
        1 => core::arch::asm!("msr SP_EL1, {v}", v = in(reg) addr),
        2 => core::arch::asm!("msr SP_EL2, {v}", v = in(reg) addr),
        // 3 => core::arch::asm!("msr SP_EL3, {v}", v = in(reg) sp.0),
        _ => panic!("invalid exception level {el}"),
    }
}

pub unsafe fn save_current_thread_state(registers: &Registers) {
    let current_thread = SCHEDULER
        .get()
        .expect("scheduler init before thread switch")
        .current_thread();
    let mut exec_state = current_thread
        .execution_state
        .try_lock()
        .expect("no locks on current thread's execution state");
    exec_state.spsr = read_saved_program_status();
    exec_state.program_counter = read_exception_link_reg();
    exec_state.stack_pointer = read_stack_pointer(0);
    exec_state.registers = *registers;
}

pub unsafe fn restore_current_thread_state(registers: &mut Registers) {
    let current_thread = SCHEDULER
        .get()
        .expect("scheduler init before thread switch")
        .current_thread();
    let exec_state = current_thread
        .execution_state
        .try_lock()
        .expect("no locks on current thread's execution state");
    *registers = exec_state.registers;
    write_stack_pointer(0, exec_state.stack_pointer);
    write_exception_link_reg(exec_state.program_counter);
    write_saved_program_status(&exec_state.spsr);
}
