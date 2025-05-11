use kernel_api::{EnvironmentValue, read_env_value};

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
    let bad_env_value = unsafe { core::mem::transmute::<usize, EnvironmentValue>(99usize) };
    assert_eq!(read_env_value(bad_env_value), 0);
}

fn supervisor_id() {
    // we are the root process
    assert_eq!(read_env_value(EnvironmentValue::CurrentSupervisorQueueId), 0);
}

fn registry_id() {
    // we are the root process
    assert_eq!(read_env_value(EnvironmentValue::CurrentRegistryQueueId), 0);
}

pub const TESTS: (&str, &[&dyn Testable]) = (
    "read_env_value",
    &[&process_id, &thread_id, &page_size, &invalid_env_value],
);
