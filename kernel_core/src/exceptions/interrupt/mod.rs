//! Interrupts are exceptions caused by hardware devices.

mod handler;
pub use handler::{Error as HandlerError, Handler};

/// The identifier of an interrupt.
pub type Id = u32;

/// Trigger mode for an interrupt.
#[derive(Debug, Default)]
pub enum TriggerMode {
    /// Use level triggering.
    #[default]
    Level,
    /// Use edge triggering.
    Edge,
}

/// The configuration of an interrupt with the interrupt controller.
#[derive(Debug, Default)]
pub struct Config {
    /// Priority level.
    pub priority: u8,
    /// Triggering mode for the interrupt.
    pub mode: TriggerMode,
}

/// An interrupt controller manages and collates interrupts for the processor.
/// This is the generic interface for the interrupt conroller mechanism.
#[cfg_attr(test, mockall::automock)]
pub trait Controller {
    /// Called once at startup to perform global initialization.
    fn global_initialize(&self);

    /// Called once per core to initialize any per-core state.
    fn initialize_for_core(&self);

    /// Interpret the contents of an `interrupts` property in a device tree node for this interrupt
    /// controller. The `index` selects which interrupt in the list to return.
    ///
    /// Returns the id and trigger mode for the interrupt.
    fn interrupt_in_device_tree(&self, data: &[u8], index: usize) -> Option<(Id, TriggerMode)>;

    /// Set the configuration of an interrupt.
    fn configure(&self, id: Id, config: &Config);

    /// Enable an interrupt to raise an exception.
    fn enable(&self, id: Id);
    /// Disable an interrupt from raising an exception.
    fn disable(&self, id: Id);

    /// Clear the pending state for this interrupt.
    fn clear_pending(&self, id: Id);

    /// Acknowledge that an interrupt exception has been handled.
    /// Returns the ID of the interrupt that was triggered.
    fn ack_interrupt(&self) -> Option<Id>;

    /// Inform the interrupt controller that the system has finished processing an interrupt.
    fn finish_interrupt(&self, id: Id);

    /// Broadcast a Software Generated Interrupt (SGI) to all other cores.
    fn broadcast_sgi(&self, sgi_id: u8);
}
