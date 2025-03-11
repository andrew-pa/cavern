# Logging Service
The logging service collects and redistributes logs from the entire system.
This includes the kernel, once it has started.
The logging service exposes the same data model as the Rust `tracing` crate, namely spans that contain events.
All IDs that are sent are made unique by including the thread ID of the sender. The process ID is also recorded.
It is up to clients to generate IDs to reduce required synchronization.
(TODO: but wouldn't it be neat to be able to like, have multiprocess spans?)

## RPC Interface

*These RPC calls do not return responses (are of type Notification) for performance:*
### Create Span
Creates a Span for the sender thread.
### Close Span
Finishes a Span by its ID, marking it complete.
### Report Event
Logs an event in the sender thread for some span.

*Regular RPC Requests:*
### Create Log Cursor
Creates a cursor that can be used to read from the log.
Cursors can either start at the beginning or the current end of the log.
### Read From Log
Read some log events at a cursor, advancing the cursor.

## Kernel Interface
The kernel will expose a system call `capture_kernel_logs` that:
- requires the caller to be a privileged process
- switches the kernel logs from the debug UART to sending messages of type 'Report Event' to the calling process,
with pid `KERNEL_FAKE_PID`.
