//! System call wrapper functions.
use super::*;

/// Reads a value from the kernel about the current process environment.
/// Unlike all other system calls, because this call is infallible, the value to be read is returned from the call instead of an error.
pub fn read_env_value(value_to_read: EnvironmentValue) -> usize {
    todo!()
}
