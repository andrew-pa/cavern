//! Interrupts from hardware devices.
use kernel_core::{
    exceptions::{interrupt::Handler, InterruptController},
    platform::device_tree::DeviceTree,
};
use log::{debug, info};
use spin::once::Once;

use crate::{
    process::thread::{PlatformScheduler, SCHEDULER},
    timer::Timer,
};

pub mod controller;
use controller::PlatformController;

/// The global interrupt handler policy.
pub static HANDLER_POLICY: Once<
    Handler<'static, 'static, 'static, Timer, PlatformController, PlatformScheduler>,
> = Once::new();

/// The current interrupt controller device in the system.
pub static CONTROLLER: Once<PlatformController> = Once::new();

/// The global instance of the system timer interface.
pub static TIMER: Once<Timer> = Once::new();

/// The length of the timer interval in `1/seconds`.
pub const TIMER_INTERVAL: u32 = 10;

/// Initialize the interrupt controller and interrupt handler.
pub fn init(device_tree: &DeviceTree<'_>) {
    debug!("Initializing interrupts…");

    // TODO: we assume here that the interrupt controller is under `/intc@?`, which is definitely
    // not true in general! We need to either use the `/interrupt-parent` property or the
    // `interrupt-controller` marker property.
    let intc_node = device_tree
        .iter_nodes_named(b"/", b"intc")
        .expect("root node")
        .next()
        .expect("have intc node");

    let controller = CONTROLLER.call_once(|| {
        controller::PlatformController::in_device_tree(intc_node.properties)
            .expect("configure interrupt controller")
    });

    controller.global_initialize();

    let timer_node = device_tree
        .iter_node_properties(b"/timer")
        .expect("have timer node");

    let timer = TIMER.call_once(|| {
        Timer::in_device_tree(timer_node, controller, TIMER_INTERVAL)
            .expect("configure system timer")
    });

    HANDLER_POLICY.call_once(|| {
        Handler::new(
            controller,
            timer,
            SCHEDULER
                .get()
                .expect("threads initialized before interrupts"),
        )
    });

    init_for_core();

    info!("Interrupts initialized!");
}

/// Perform initialization for interrupts that needs to happen for each core on the system.
pub fn init_for_core() {
    let ctrl = CONTROLLER.get().unwrap();
    ctrl.initialize_for_core();
    TIMER.get().unwrap().start_for_core(ctrl);
}

/// Wait for an interrupt to occur, pausing execution.
#[inline]
pub fn wait_for_interrupt() {
    unsafe {
        core::arch::asm!("wfi");
    }
}
