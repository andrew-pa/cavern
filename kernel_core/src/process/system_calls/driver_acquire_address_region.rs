use alloc::sync::Arc;

use kernel_api::{flags::DriverAddressRegionFlags, PrivilegeLevel};
use snafu::{ensure, OptionExt, ResultExt};

use crate::{
    memory::{
        active_user_space_tables::{ActiveUserSpaceTables, ActiveUserSpaceTablesChecker},
        page_table::{MemoryKind, MemoryProperties},
        PageAllocator, PhysicalAddress,
    },
    process::{
        queue::QueueManager,
        system_calls::{
            InvalidAddressSnafu, InvalidFlagsSnafu, InvalidLengthSnafu, ManagerSnafu,
            NotPermittedSnafu, OutOfBoundsSnafu,
        },
        thread::{Registers, ThreadManager},
        ProcessManager, Thread,
    },
};

use super::{Error, SystemCalls};

impl<PA: PageAllocator, PM: ProcessManager, TM: ThreadManager, QM: QueueManager>
    SystemCalls<'_, '_, PA, PM, TM, QM>
{
    #[allow(clippy::unused_self)]
    pub(super) fn syscall_driver_acquire_address_region<AUST: ActiveUserSpaceTables>(
        &self,
        current_thread: &Arc<Thread>,
        registers: &Registers,
        user_space_memory: ActiveUserSpaceTablesChecker<'_, AUST>,
    ) -> Result<(), Error> {
        let proc = current_thread.parent.as_ref().unwrap();
        ensure!(
            proc.props.privilege == PrivilegeLevel::Driver,
            NotPermittedSnafu {
                reason: "caller is not a driver",
            }
        );

        let flags =
            DriverAddressRegionFlags::from_bits(registers.x[0]).context(InvalidFlagsSnafu {
                reason: "invalid flag bits",
                bits: registers.x[0],
            })?;
        let base: PhysicalAddress = registers.x[1].into();
        let size: usize = registers.x[2];
        ensure!(
            size > 0,
            InvalidLengthSnafu {
                reason: "zero size",
                length: size
            }
        );

        let bytes = size
            .checked_mul(usize::from(self.page_allocator.page_size()))
            .context(InvalidLengthSnafu {
                reason: "size overflow",
                length: size,
            })?;
        let (ram_start, ram_len) = self.page_allocator.memory_range();
        let ram_start = usize::from(ram_start);
        let ram_end = ram_start + ram_len;
        let region_start = usize::from(base);
        let region_end = region_start
            .checked_add(bytes)
            .context(InvalidLengthSnafu {
                reason: "address overflow",
                length: bytes,
            })?;
        ensure!(
            region_end <= ram_start || region_start >= ram_end,
            OutOfBoundsSnafu {
                reason: "address in RAM",
                ptr: region_start,
            }
        );

        let out_ptr: &mut usize = user_space_memory
            .check_mut_ref(registers.x[3].into())
            .context(InvalidAddressSnafu { cause: "output" })?;

        let mut props = MemoryProperties {
            user_space_access: true,
            writable: !flags.contains(DriverAddressRegionFlags::READ_ONLY),
            executable: false,
            ..MemoryProperties::default()
        };
        props.kind = if flags.contains(DriverAddressRegionFlags::ENABLE_CACHE) {
            MemoryKind::Normal
        } else {
            MemoryKind::Device
        };

        let va = proc
            .map_driver_region(base, size, &props)
            .context(ManagerSnafu)?;
        *out_ptr = va.into();
        Ok(())
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
    fn acquire_success() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(600).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: PrivilegeLevel::Driver,
            },
            ThreadId::new(601).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let phys = {
            let (start, len) = pa.memory_range();
            PhysicalAddress::from(usize::from(start) + len + usize::from(pa.page_size()))
        };
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
        assert_ne!(out, 0);
        assert!(proc
            .driver_mappings
            .lock()
            .iter()
            .any(|(addr, _)| *addr == out.into()));

        // cleanup
        let _ = proc.unmap_driver_region(out.into());
    }

    #[test]
    fn acquire_invalid_pointer() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(610).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: PrivilegeLevel::Driver,
            },
            ThreadId::new(611).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let phys = pa.allocate(1).unwrap();
        let mut regs = Registers::default();
        regs.x[0] = 0;
        regs.x[1] = usize::from(phys);
        regs.x[2] = 1;
        regs.x[3] = 0; // invalid pointer

        assert_matches!(
            policy.dispatch_system_call(
                CallNumber::DriverAcquireAddressRegion.into_integer(),
                &current_thread,
                &regs,
                &usm
            ),
            Err(Error::InvalidAddress { .. })
        );
        pa.free(phys, 1).unwrap();
    }

    #[test]
    fn acquire_address_in_ram() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(615).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: PrivilegeLevel::Driver,
            },
            ThreadId::new(616).unwrap(),
        )
        .unwrap();
        let current_thread = proc.threads.read().first().unwrap().clone();
        let pm = MockProcessManager::new();
        let tm = MockThreadManager::new();
        let qm = MockQueueManager::new();
        let policy = SystemCalls::new(pa, &pm, &tm, &qm);
        let usm = AlwaysValidActiveUserSpaceTables::new(pa.page_size());

        let phys = PhysicalAddress::from(0x1000usize);
        let mut out = 0usize;
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
            Err(Error::OutOfBounds { .. })
        );
    }

    #[test]
    fn acquire_not_driver() {
        let pa = &*PAGE_ALLOCATOR;
        let proc = crate::process::tests::create_test_process(
            ProcessId::new(620).unwrap(),
            Properties {
                supervisor_queue: None,
                registry_queue: None,
                privilege: PrivilegeLevel::Privileged,
            },
            ThreadId::new(621).unwrap(),
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
            Err(Error::NotPermitted { .. })
        );
        pa.free(phys, 1).unwrap();
    }
}
