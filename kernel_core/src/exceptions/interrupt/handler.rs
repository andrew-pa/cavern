use crate::{platform::timer::SystemTimer, process::thread::Scheduler};
use log::{debug, trace, warn};

use super::Id as InterruptId;

/// Interrupt handler policy.
pub struct Handler<'ic, 'sc, 't, T: SystemTimer, IC: super::Controller, Sched: Scheduler> {
    controller: &'ic IC,
    timer: &'t T,
    scheduler: &'sc Sched,
}

/// An error that could occur during handling an interrupt.
#[derive(Debug)]
pub enum Error {
    /// An interrupt occurred that was unexpected.
    UnknownInterrupt(InterruptId),
}

impl<'ic, 'sc, 't, T: SystemTimer, IC: super::Controller, Sched: Scheduler>
    Handler<'ic, 'sc, 't, T, IC, Sched>
{
    /// Create a new interrupt handler policy.
    pub fn new(controller: &'ic IC, timer: &'t T, scheduler: &'sc Sched) -> Self {
        Self {
            controller,
            timer,
            scheduler,
        }
    }

    /// Acknowledge any interrupts that have occurred, and handle the ones that are known.
    ///
    /// # Errors
    /// If an error occurs, the thread state is not be restored.
    ///
    /// - [`Error::UnknownInterrupt`]: If an interrupt happens that is unknown to the handler.
    pub fn process_interrupts(&self) -> Result<(), Error> {
        while let Some(int_id) = self.controller.ack_interrupt() {
            trace!("handling interrupt {int_id}");

            if int_id == self.timer.interrupt_id() {
                debug!("timer interrupt");
                self.scheduler.next_time_slice();
                self.timer.reset();
            } else if int_id == 0 {
                // another core has panicked
                warn!("panic on other core, halting");
                // this is somewhat inelegant (halting is an effect after all), but since panics
                // themselves are both rare and inelegant it is fine for now.
                loop { }
            } else {
                return Err(Error::UnknownInterrupt(int_id));
            }

            trace!("finished interrupt {int_id}");
            self.controller.finish_interrupt(int_id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;

    use crate::{
        exceptions::{interrupt::MockController, InterruptId},
        platform::timer::MockSystemTimer,
        process::thread::MockScheduler,
    };

    use super::{Error, Handler};

    #[test]
    fn unknown_interrupt() {
        let unknown_id = 1000;
        let mut controller = MockController::new();
        let mut timer = MockSystemTimer::new();
        let sched = MockScheduler::new();
        controller
            .expect_ack_interrupt()
            .once()
            .return_const(Some(unknown_id));
        timer.expect_interrupt_id().once().return_const(30u32);
        let h = Handler::new(&controller, &timer, &sched);
        let res = h.process_interrupts();
        assert!(matches!(res, Err(Error::UnknownInterrupt(id)) if id == unknown_id));
    }

    #[test]
    fn run_scheduler_on_timer_interrupt() {
        let timer_id: InterruptId = 30;
        let mut controller = MockController::new();
        let mut timer = MockSystemTimer::new();
        let mut sched = MockScheduler::new();
        sched.expect_next_time_slice().once().return_const(());
        controller
            .expect_ack_interrupt()
            .once()
            .return_const(Some(timer_id));
        controller
            .expect_finish_interrupt()
            .once()
            .with(eq(timer_id))
            .return_const(());
        controller.expect_ack_interrupt().once().return_const(None);
        timer.expect_interrupt_id().once().return_const(timer_id);
        timer.expect_reset().once().return_const(());
        let h = Handler::new(&controller, &timer, &sched);
        h.process_interrupts().expect("handle interrupt");
    }
}
