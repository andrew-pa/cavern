//! Thread scheduler implementation.
use core::marker::PhantomData;

use super::{Scheduler, State, Thread};
use crate::platform::cpu::{CpuIdReader, Id as CpuId};
use alloc::{sync::Arc, vec::Vec};
use arc_swap::ArcSwap;
use crossbeam::queue::SegQueue;
use hashbrown::HashMap;

/// A simple round-robin thread scheduler.
pub struct RoundRobinScheduler<C: CpuIdReader> {
    queues: HashMap<CpuId, SegQueue<Arc<Thread>>>,
    current_threads: HashMap<CpuId, ArcSwap<Thread>>,
    cpu_id_reader: PhantomData<C>,
}

impl<C: CpuIdReader> RoundRobinScheduler<C> {
    /// Create a new scheduler.
    ///
    /// The vector `cpus` contains a set of CPU id, idle thread pairs for each core in the system.
    /// Each idle thread must be distinct, and will run first.
    /// The CPU ids must match those provided by [`CpuIdReader::current_cpu()`] given `C`.
    #[must_use]
    pub fn new(cpus: Vec<(CpuId, Arc<Thread>)>) -> Self {
        RoundRobinScheduler {
            queues: cpus.iter().map(|(id, _)| (*id, SegQueue::new())).collect(),
            current_threads: cpus
                .iter()
                .map(|(id, idle_thread)| (*id, idle_thread.clone().into()))
                .collect(),
            cpu_id_reader: PhantomData,
        }
    }
}

impl<C: CpuIdReader> Scheduler for RoundRobinScheduler<C> {
    fn current_thread(&self) -> Arc<Thread> {
        self.current_threads
            .get(&C::current_cpu())
            .expect("cpu has current thread")
            .load_full()
    }

    fn next_time_slice(&self) {
        let cpu_id = C::current_cpu();
        let mut next_thread = None;
        let queue = self.queues.get(&cpu_id).expect("cpu has queue");
        for _ in 0..queue.len() {
            match queue.pop() {
                Some(t) => match t.state() {
                    State::Running => {
                        next_thread = Some(t);
                        break;
                    }
                    _ => {
                        queue.push(t);
                    }
                },
                None => {
                    break;
                }
            }
        }
        if let Some(next_thread) = next_thread {
            let last_thread = self
                .current_threads
                .get(&cpu_id)
                .expect("cpu has current thread")
                .swap(next_thread);
            queue.push(last_thread);
        }
    }
}
