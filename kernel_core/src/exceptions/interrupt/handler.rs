use core::marker::PhantomData;

use crate::{
    platform::timer::SystemTimer,
    process::thread::{Scheduler, Switcher as ThreadSwitcher},
};
use log::{debug, trace};

use super::Id as InterruptId;

/// Interrupt handler policy.
pub struct Handler<
    'ic,
    'sc,
    't,
    T: SystemTimer,
    IC: super::Controller,
    Sched: Scheduler,
    TS: ThreadSwitcher,
> {
    controller: &'ic IC,
    timer: &'t T,
    scheduler: &'sc Sched,
    thread_switcher: PhantomData<TS>,
}

/// An error that could occur during handling an interrupt.
#[derive(Debug)]
pub enum Error {
    /// An interrupt occurred that was unexpected.
    UnknownInterrupt(InterruptId),
}

impl<'ic, 'sc, 't, T: SystemTimer, IC: super::Controller, Sched: Scheduler, TS: ThreadSwitcher>
    Handler<'ic, 'sc, 't, T, IC, Sched, TS>
{
    /// Create a new interrupt handler policy.
    pub fn new(controller: &'ic IC, timer: &'t T, scheduler: &'sc Sched) -> Self {
        Self {
            controller,
            timer,
            scheduler,
            thread_switcher: PhantomData,
        }
    }

    /// Acknowledge any interrupts that have occurred, and handle the ones that are known.
    ///
    /// # Errors
    /// If an error occurs, the thread state is not be restored.
    ///
    /// - [`Error::UnknownInterrupt`]: If an interrupt happens that is unknown to the handler.
    pub fn process_interrupts(&self) -> Result<(), Error> {
        unsafe {
            let current = self.scheduler.current_thread();
            TS::save_thread_state(current.as_ref());
        }
        while let Some(int_id) = self.controller.ack_interrupt() {
            trace!("handling interrupt {int_id}");

            if int_id == self.timer.interrupt_id() {
                debug!("timer interrupt");
                self.scheduler.next_time_slice();
                self.timer.reset();
            } else {
                return Err(Error::UnknownInterrupt(int_id));
            }

            trace!("finished interrupt {int_id}");
            self.controller.finish_interrupt(int_id);
        }
        unsafe {
            let current = self.scheduler.current_thread();
            TS::restore_thread_state(current.as_ref());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;
    use std::sync::Arc;

    use mockall::predicate::{eq, function};

    use crate::{
        exceptions::{interrupt::MockController, InterruptId},
        platform::timer::MockSystemTimer,
        process::thread::{MockScheduler, MockSwitcher, Thread},
    };

    use super::{Error, Handler};

    #[test]
    fn unknown_interrupt() {
        let unknown_id = 1000;
        let mut controller = MockController::new();
        let mut timer = MockSystemTimer::new();
        let mut sched = MockScheduler::new();
        let the_thread = Arc::new(Thread {});
        let the_thread_2 = the_thread.clone();
        sched
            .expect_current_thread()
            .once()
            .returning(move || the_thread_2.clone());
        let save_cx = MockSwitcher::save_thread_state_context();
        save_cx
            .expect()
            .once()
            .with(function(move |a| ptr::eq(a, the_thread.as_ref())))
            .return_const(());
        controller
            .expect_ack_interrupt()
            .once()
            .return_const(Some(unknown_id));
        timer.expect_interrupt_id().once().return_const(30u32);
        let h = Handler::<_, _, _, MockSwitcher>::new(&controller, &timer, &sched);
        let res = h.process_interrupts();
        assert!(matches!(res, Err(Error::UnknownInterrupt(id)) if id == unknown_id));
    }

    #[test]
    fn run_scheduler_on_timer_interrupt() {
        let timer_id: InterruptId = 30;
        let mut controller = MockController::new();
        let mut timer = MockSystemTimer::new();
        let mut sched = MockScheduler::new();
        let the_thread = Arc::new(Thread {});
        let the_thread_2 = the_thread.clone();
        let the_thread_3 = the_thread.clone();
        sched
            .expect_current_thread()
            .times(2)
            .returning(move || the_thread_2.clone());
        sched.expect_next_time_slice().once().return_const(());
        let save_cx = MockSwitcher::save_thread_state_context();
        save_cx
            .expect()
            .once()
            .with(function(move |a| ptr::eq(a, the_thread.as_ref())))
            .return_const(());
        let restore_cx = MockSwitcher::restore_thread_state_context();
        restore_cx
            .expect()
            .once()
            .with(function(move |a| ptr::eq(a, the_thread_3.as_ref())))
            .return_const(());
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
        let h = Handler::<_, _, _, MockSwitcher>::new(&controller, &timer, &sched);
        h.process_interrupts().expect("handle interrupt");
    }
}
