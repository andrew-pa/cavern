use alloc::sync::Arc;

use snafu::ResultExt;

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        PageAllocator,
    },
    process::{
        queue::QueueManager,
        system_calls::InvalidAddressSnafu,
        thread::{Registers, ThreadManager},
        ProcessManager, Thread,
    },
};

use super::{Error, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    #[allow(clippy::unused_self)]
    pub(super) fn syscall_write_log<AUST: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, AUST>,
    ) -> Result<(), Error> {
        let level = match registers.x[0] {
            1 => log::Level::Error,
            2 => log::Level::Warn,
            3 => log::Level::Info,
            4 => log::Level::Debug,
            5 => log::Level::Trace,
            _ => {
                return Err(Error::InvalidFlags {
                    reason: "unknown log level".into(),
                    bits: registers.x[0],
                })
            }
        };

        let msg_data = user_space_memory
            .check_slice::<u8>(registers.x[1].into(), registers.x[2])
            .context(InvalidAddressSnafu {
                cause: "message slice",
            })?;

        let msg = unsafe { core::str::from_utf8_unchecked(msg_data) };

        let pid = current_thread.parent.as_ref().unwrap().id;
        let tid = current_thread.id;

        log::logger().log(
            &log::Record::builder()
                .level(level)
                .args(format_args!("({pid}:{tid}) {msg}"))
                .module_path_static(Some("u"))
                .build(),
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use std::assert_matches::assert_matches;

    use kernel_api::{CallNumber, ProcessId};

    use crate::{
        memory::active_user_space_tables::AlwaysValidActiveUserSpaceTables,
        process::{
            queue::MockQueueManager, system_calls::SysCallEffect, tests::PAGE_ALLOCATOR,
            thread::MockThreadManager, MockProcessManager, Properties, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn write_log_success() {
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(230).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(231).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pa = &*PAGE_ALLOCATOR;
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let msg = b"hello-logger";
        let mut regs = Registers::default();
        regs.x[0] = 3; // Info level
        regs.x[1] = msg.as_ptr() as usize;
        regs.x[2] = msg.len();

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::WriteLogMessage.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
    }

    #[test]
    fn write_log_invalid_level() {
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(232).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: kernel_api::PrivilegeLevel::Privileged,
            },
            ThreadId::new(233).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();

        let pa = &*PAGE_ALLOCATOR;
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = 7; // invalid level (allowed 1-5)
        regs.x[1] = b"x".as_ptr() as usize;
        regs.x[2] = 1;

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::WriteLogMessage.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::InvalidFlags { .. })
        );
    }
}
