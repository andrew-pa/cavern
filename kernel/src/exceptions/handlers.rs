//! The exception vector and handler functions.

use bytemuck::Contiguous;
use kernel_api::{CallNumber, ExitReason};
use log::{debug, error};

use crate::{
    memory::{page_allocator, SystemActiveUserSpaceTables},
    process::{
        thread::{restore_current_thread_state, save_current_thread_state, SCHEDULER},
        PROCESS_MANAGER, SYS_CALL_POLICY,
    },
};
use kernel_core::{
    exceptions::ExceptionSyndromeRegister,
    memory::PageAllocator,
    process::{
        system_calls::SysCallEffect,
        thread::{Registers, Scheduler},
        ProcessManager,
    },
};

// assembly definition of the exception vector table and the low level code that installs the table
// and the low level handlers that calls into the Rust code.
core::arch::global_asm!(include_str!("exception_vector.S"));

extern "C" {
    /// Install the kernel's exception vector table so the kernel can handle exceptions.
    ///
    /// This function should only be called once at initialization, ideally as early as possible to
    /// catch kernel runtime errors.
    ///
    /// # Safety
    /// This function should be safe as long as `table.S` is correct.
    pub fn install_exception_vector();
}

#[no_mangle]
unsafe extern "C" fn handle_synchronous_exception(regs: *mut Registers, esr: usize, far: usize) {
    let esr = ExceptionSyndromeRegister(esr as u64);

    let regs = regs
        .as_mut()
        .expect("asm exception vector code passes non-null ptr to registers object");
    let current_thread = save_current_thread_state(regs);

    if esr.ec().is_system_call() {
        let user_space_mem = SystemActiveUserSpaceTables::new(page_allocator().page_size());
        let result = SYS_CALL_POLICY
            .get()
            .expect("system call handler policy to be initialized before system calls are made")
            .dispatch_system_call(esr.iss() as u16, &current_thread, regs, &user_space_mem);
        match result {
            Ok(SysCallEffect::Return(result)) => {
                restore_current_thread_state(regs, result);
            }
            Ok(SysCallEffect::ScheduleNextThread) => {
                SCHEDULER.get().unwrap().next_time_slice();
                restore_current_thread_state(regs, None);
            }
            Err(e) => {
                debug!(
                    "system call 0x{:x} ({:?}) from thread #{} failed: {}",
                    esr.iss(),
                    CallNumber::from_integer(esr.iss() as u16),
                    current_thread.id,
                    snafu::Report::from_error(&e)
                );
                restore_current_thread_state(regs, e.to_code().into_integer());
            }
        }
    } else if esr.ec().is_user_space_code_page_fault() || esr.ec().is_kernel_data_page_fault() {
        error!(
            "user space page fault in thread #{}, process #{}! {}, FAR={far:x}, registers = {:x?}",
            current_thread.id,
            current_thread.parent.as_ref().map_or(0, |p| p.id.get()),
            esr,
            regs
        );

        PROCESS_MANAGER
            .get()
            .unwrap()
            .exit_thread(&current_thread, ExitReason::page_fault())
            .expect("kill thread");

        SCHEDULER.get().unwrap().next_time_slice();

        restore_current_thread_state(regs, None);
    } else {
        panic!(
            "synchronous exception! {}, FAR={far:x}, registers = {:x?}",
            esr, regs
        );
    }
}

#[no_mangle]
unsafe extern "C" fn handle_interrupt(regs: *mut Registers, _esr: usize, _far: usize) {
    let regs = regs
        .as_mut()
        .expect("asm exception vector code passes non-null ptr to registers object");
    save_current_thread_state(regs);
    super::interrupt::HANDLER_POLICY
        .get()
        .expect("interrupt handler policy to be initialized before interrupts are enabled")
        .process_interrupts()
        .expect("interrupt handlers to complete successfully");
    restore_current_thread_state(regs, None);
}

#[no_mangle]
unsafe extern "C" fn handle_fast_interrupt(regs: *mut Registers, esr: usize, far: usize) {
    panic!(
        "fast interrupt! {}, FAR={far:x}, registers = {:?}",
        ExceptionSyndromeRegister(esr as u64),
        regs.as_ref()
    );
}

#[no_mangle]
unsafe extern "C" fn handle_system_error(regs: *mut Registers, esr: usize, far: usize) {
    panic!(
        "system error! ESR={esr:x}, FAR={far:x}, registers = {:?}",
        regs.as_ref()
    );
}

#[no_mangle]
unsafe extern "C" fn handle_unimplemented_exception(regs: *mut Registers, esr: usize, far: usize) {
    panic!(
        "unimplemented exception! {}, FAR={far:x}, registers = {:?}",
        ExceptionSyndromeRegister(esr as u64),
        regs.as_ref()
    );
}
