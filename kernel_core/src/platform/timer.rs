//! Interface for system timer mechanism used for time slicing.

/// System timer mechanism used for time slicing.
#[cfg_attr(test, mockall::automock)]
pub trait SystemTimer {
    /// The ID of the interrupt that is triggered when the timer expires.
    fn interrupt_id(&self) -> crate::exceptions::InterruptId;

    /// Reset the timer after it has expired.
    fn reset(&self);
}
