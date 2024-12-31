//! The exception vector and handler functions.

use bytemuck::Contiguous;
use kernel_api::CallNumber;
use log::{error, warn};

use crate::process::{
    thread::{restore_current_thread_state, save_current_thread_state},
    SYS_CALL_POLICY,
};
use kernel_core::{exceptions::ExceptionSyndromeRegister, process::thread::Registers};

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

    if esr.ec().is_system_call() {
        let regs = regs
            .as_mut()
            .expect("asm exception vector code passes non-null ptr to registers object");
        let current_thread = save_current_thread_state(regs);
        if let Some(call_num) = CallNumber::from_integer(esr.iss() as u16) {
            let result = SYS_CALL_POLICY
                .get()
                .expect("system call handler policy to be initialized before system calls are made")
                .dispatch_system_call(call_num, &current_thread, regs)
                .unwrap_or_else(|e| {
                    warn!("system call failed: {e}");
                    e.to_code().into_integer()
                });
            regs.x[0] = result;
        } else {
            error!("invalid system call number {}", esr.iss());
            todo!("kill offending process with a fault");
        }
        restore_current_thread_state(regs);
    } else {
        panic!(
            "synchronous exception! {}, FAR={far:x}, registers = {:x?}",
            esr,
            regs.as_ref()
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
    restore_current_thread_state(regs);
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
