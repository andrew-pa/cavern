//! Thread switching mechanism.

use alloc::{sync::Arc, vec::Vec};
use itertools::Itertools;
use kernel_api::{ExitMessage, ExitReason};
use kernel_core::{
    collections::HandleMap,
    memory::{AddressSpaceIdPool, VirtualAddress},
    platform::cpu::{CoreInfo, CpuIdReader, Id as CpuId},
    process::{
        queue::QueueManager,
        thread::{
            scheduler::RoundRobinScheduler, ProcessorState, Registers, SavedProgramStatus,
            Scheduler, State, Thread, ThreadManager, MAX_THREAD_ID,
        },
        ManagerError,
    },
};
use log::{debug, info, trace};
use spin::once::Once;

use crate::memory::switch_el0_context;

/// Implementation of [`CpuIdReader`] that reads the real system registers.
pub struct SystemCpuIdReader;

impl CpuIdReader for SystemCpuIdReader {
    fn current_cpu() -> CpuId {
        let mut core_id: usize;
        unsafe {
            core::arch::asm!(
                "mrs {core_id}, MPIDR_EL1",
                core_id = out(reg) core_id
            );
        }
        // clear multiprocessor flag bit in MPIDR register
        core_id & !0x8000_0000
    }
}

/// Read the current value of the `SPSR_EL1` register.
#[must_use]
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
#[must_use]
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
#[must_use]
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

pub struct SystemThreadManager<S: Scheduler> {
    scheduler: PlatformScheduler,
    threads: HandleMap<Thread>,
    asid_pool: AddressSpaceIdPool,
}

/// The platform selected thread scheduler.
pub type PlatformScheduler = RoundRobinScheduler<SystemCpuIdReader>;

/// The system thread manager instance.
pub static THREAD_MANAGER: Once<SystemThreadManager<PlatformScheduler>> = Once::new();

/// Initialize the thread scheduler.
pub fn init(cores: &[CoreInfo]) {
    debug!("Initalizing threads...");

    THREAD_MANAGER.call_once(|| {
        let threads = HandleMap::new(MAX_THREAD_ID);

        let init_threads: Vec<_> = cores
            .iter()
            .map(|info| {
                let id = threads.preallocate_handle().unwrap();
                let idle_thread = Arc::new(Thread::new(
                    id,
                    None,
                    State::Running,
                    unsafe { ProcessorState::new_for_idle_thread() },
                    (VirtualAddress::null(), 0),
                ));
                threads.insert_with_handle(id, idle_thread.clone());
                (info.id, idle_thread)
            })
            .collect();

        SystemThreadManager {
            threads,
            scheduler: PlatformScheduler::new(&init_threads),
            asid_pool: AddressSpaceIdPool::default(),
        }
    });

    info!("Threads initialized!");
}

impl SystemThreadManager<S: Scheduler> {
    /// Save the currently executing thread state.
    /// Returns a reference to the current thread.
    ///
    /// # Safety
    /// This function is only safe to call when the currently running thread has been suspended, i.e.
    /// in an exception handler. Also, this function assumes that the currently running thread is the
    /// one that the scheduler believes is currently running (which should always be true).
    pub unsafe fn save_current_thread_state(&self, registers: &Registers) -> Arc<Thread> {
        // Determine the current running thread according to the scheduler.
        // We assume that this thread is the one currently executing on this processor.
        let current_thread = self.scheduler.current_thread();

        // Save the processor state into the thread object.
        {
            let mut s = current_thread
                .processor_state
                .try_lock()
                .expect("no locks on current thread's execution state");
            s.spsr = read_saved_program_status();
            s.program_counter = read_exception_link_reg();
            s.stack_pointer = read_stack_pointer(0);
            s.registers = *registers;

            // trace!(
            //     "saving processor state to thread#{}, pc={:?}",
            //     current_thread.id,
            //     s.program_counter
            // );
        }

        current_thread
    }

    /// Restore the currently scheduled thread as the currently executing one.
    ///
    /// If `return_value` is `Some`, then `x0` will be set to the value, "returning" the value to the
    /// current thread.
    ///
    /// # Safety
    /// This function is only safe to call at the end of an exception handler when the currently
    /// executing thread is about to be restored.
    /// Additionally, returning a value is only safe if the current thread is expecting it.
    pub unsafe fn restore_current_thread_state(
        &self,
        registers: &mut Registers,
        return_value: impl Into<Option<usize>>,
    ) {
        // Determine the current running thread according to the scheduler.
        let current_thread = self.scheduler.current_thread();

        assert!(current_thread.state() == State::Running);

        // Switch to this thread's process' page table, if it is a user space thread.
        if let Some(process) = current_thread.parent.as_ref() {
            let (asid, full_flush) = process.get_address_space_id(&self.asid_pool);
            let pt = process.page_tables.read();
            switch_el0_context(&pt, asid, full_flush);
        }

        // Restore the state of the processor.
        let s = current_thread
            .processor_state
            .try_lock()
            .expect("no locks on current thread's execution state");
        *registers = s.registers;
        // write x0 after restoring the rest of the saved registers to ensure that the return value
        // makes it back to the caller thread.
        if let Some(rv) = return_value.into() {
            registers.x[0] = rv;
        }
        write_stack_pointer(0, s.stack_pointer);
        write_exception_link_reg(s.program_counter);
        write_saved_program_status(&s.spsr);

        // trace!(
        //     "restoring processor state to thread#{}, pc={:?}",
        //     current_thread.id,
        //     s.program_counter,
        // );
    }

    /// Update the scheduler for a new time slice, potentially scheduling a new current thread.
    pub fn next_time_slice(&self) {
        self.scheduler.next_time_slice();
    }
}

impl<S: Scheduler> ThreadManager for SystemThreadManager<S> {
    fn spawn_thread(
        &self,
        parent_process: Arc<Process>,
        entry_point: VirtualAddress,
        stack_size: usize,
        user_data: usize,
    ) -> Result<Arc<Thread>, ManagerError> {
        let id = self
            .threads
            .preallocate_handle()
            .context(OutOfHandlesSnafu)?;
        trace!("spawning thread #{id}");
        let stack = parent_process.allocate_memory(
            page_allocator(),
            stack_size,
            MemoryProperties {
                writable: true,
                executable: false,
                user_space_access: true,
                ..MemoryProperties::default()
            },
        )?;
        let stack_ptr = stack.byte_add(stack_size * page_allocator().page_size());
        let pstate = ProcessorState::new_for_user_thread(entry_point, stack_ptr, user_data);
        debug!("creating thread #{id} in process #{}, entry point @ {entry_point:?}, stack @ {stack_ptr:?}", parent_process.id);
        let thread = Arc::new(Thread::new(
            id,
            Some(parent_process.clone()),
            State::Running,
            pstate,
            (stack, stack_size),
        ));
        {
            let mut ts = parent_process.threads.write();
            ts.push(thread.clone());
        }
        self.threads.insert_with_handle(id, thread.clone());
        self.scheduler.spawn_new_thread(thread.clone());
        Ok(thread)
    }

    fn exit_thread(&self, thread: &Arc<Thread>, reason: ExitReason) -> Result<bool, ManagerError> {
        debug!("thread #{} exited with reason {reason:?}", thread.id);

        // remove current thread from scheduler, set state to finished
        thread.set_state(State::Finished);

        // remove thread from parent process
        let parent = thread
            .parent
            .as_ref()
            .expect("kernel idle threads don't exit");
        let last_thread = {
            let mut ts = parent.threads.write();
            let (i, _) = ts
                .iter()
                .find_position(|t| t.id == thread.id)
                .expect("find thread in parent");
            ts.swap_remove(i);
            ts.is_empty()
        };

        // free thread stack
        parent.free_memory(page_allocator(), thread.stack.0, thread.stack.1)?;

        if last_thread {
            // if this was the last thread, the parent process is now also finished
            debug!("last thread in process exited");
            self.exit_process(parent, reason)?;
        } else {
            // notify exit subscribers that a thread exited
            let msg = ExitMessage::thread(thread.id, reason);
            for qu in thread.exit_subscribers.lock().iter() {
                trace!("sending exit message {msg:?} to queue #{}", qu.id);
                qu.send(bytemuck::bytes_of(&msg), core::iter::empty())?;
            }
        }

        // remove thread from handle table
        self.threads
            .remove(thread.id)
            .expect("thread is in thread handle table");

        Ok(last_thread)
    }

    fn thread_for_id(&self, thread_id: ThreadId) -> Option<Arc<Thread>> {
        self.threads.get(thread_id)
    }
}
