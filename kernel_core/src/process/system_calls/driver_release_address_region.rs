use alloc::{format, sync::Arc};

use kernel_api::PrivilegeLevel;
use snafu::{ensure, ResultExt};

use crate::{
    memory::{PageAllocator, VirtualAddress},
    process::{
        queue::QueueManager,
        system_calls::{ManagerSnafu, NotPermittedSnafu},
        thread::{Registers, ThreadManager},
        ProcessManager, Thread,
    },
};

use super::{Error, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    #[allow(clippy::unused_self)]
    pub(super) fn syscall_driver_release_address_region(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
    ) -> Result<(), Error> {
        let proc = current_thread.parent.as_ref().unwrap();
        ensure!(
            proc.props.privilege == PrivilegeLevel::Driver,
            NotPermittedSnafu {
                reason: "caller is not a driver",
            }
        );
        let va: VirtualAddress = registers.x[0].into();
        proc.unmap_driver_region(va).with_context(|_| ManagerSnafu {
            reason: format!("unmap driver region at {va:?} from process address space"),
        })
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Contiguous;
    use std::assert_matches::assert_matches;

    use kernel_api::{CallNumber, ProcessId};

    use crate::{
        memory::{active_user_space_tables::AlwaysValidActiveUserSpaceTables, PageAllocator},
        process::{
            queue::MockQueueManager, system_calls::SysCallEffect, tests::PAGE_ALLOCATOR,
            thread::MockThreadManager, MockProcessManager, Properties, ThreadId,
        },
    };

    use super::*;

    #[test]
    fn release_success() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(700).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: PrivilegeLevel::Driver,
            },
            ThreadId::new(701).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let phys = pa.allocate(1).unwrap();
        let mut out: usize = 0;
        let mut regs = Registers::default();
        regs.x[0] = 0;
        regs.x[1] = usize::from(phys);
        regs.x[2] = 1;
        regs.x[3] = (&mut out) as *mut usize as usize;
        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::DriverAcquireAddressRegion.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
        let mut regs = Registers::default();
        regs.x[0] = out;
        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::DriverReleaseAddressRegion.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Ok(SysCallEffect::Return(0))
        );
        pa.free(phys, 1).unwrap();
    }

    #[test]
    fn release_not_found() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(710).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: PrivilegeLevel::Driver,
            },
            ThreadId::new(711).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let mut regs = Registers::default();
        regs.x[0] = 0xdeadbeef;
        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::DriverReleaseAddressRegion.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::NotFound { .. })
        );
    }
}
