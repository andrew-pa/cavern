use kernel_api::{CallNumber, EnvironmentValue, read_env_value};
use crate::Testable;

fn process_id() {
    assert_eq!(read_env_value(EnvironmentValue::CurrentProcessId), 1);
}

fn thread_id() {
    // this value depends on the number of processors since each processor gets an idle thread
    assert!(read_env_value(EnvironmentValue::CurrentThreadId) >= 1);
}

fn page_size() {
    // TODO: this won't always be true
    assert_eq!(read_env_value(EnvironmentValue::PageSizeInBytes), 4096);
}

fn invalid_env_value() {
    let value_to_read: u32 = 0xffff_0bad;
    let mut result: usize;
    unsafe {
        core::arch::asm!(
            "mov x0, {val_to_read:x}",
            "svc {call_number}",
            "mov {res}, x0",
            val_to_read = in(reg) value_to_read,
            res = out(reg) result,
            call_number = const core::mem::transmute::<_, u16>(CallNumber::ReadEnvValue)
        );
    }
    assert_eq!(result, 0);
}

fn supervisor_id() {
    // we are the root process
    assert_eq!(
        read_env_value(EnvironmentValue::CurrentSupervisorQueueId),
        0
    );
}

fn registry_id() {
    // we are the root process
    assert_eq!(read_env_value(EnvironmentValue::CurrentRegistryQueueId), 0);
}

pub const TESTS: (&str, &[&dyn Testable]) = (
    "read_env_value",
    &[
        &process_id,
        &thread_id,
        &page_size,
        &invalid_env_value,
        &supervisor_id,
        &registry_id,
    ],
);
