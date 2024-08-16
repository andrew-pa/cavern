<center>
# **Endless Hole: Kernel** #
</center>

This document describes the Endless Hole microkernel.

The kernel is responsible for managing the most fundamental system mechanisms: time and space, or in other words: thread scheduling and memory mapping/allocation.
In addition, the kernel provides a mechanism for processes in the system to communicate with each other through messages and shared memory.
Finally, the kernel also takes care of handling interrupts from devices and notifying the responsible driver.

# Overview
## Processes and Threads
### Processes
A process is a collection of threads who share the same:

- process ID
- memory address space and memory loans
- supervisor process ID
- role (process level and supervisor status)
- exit state: running, successfully exited with some code, exited with a fault

Processes start with a single main thread running at their entry point.
Processes run until they exit or encounter a fault.
When a process exits for any reason, the parent of the process can be notified.
Processes exit successfully when their last thread exits, and have the exit code provided by this last exit.

Process IDs start from 1.

### Process Roles
The supervisor process is the process responsible for resource resolution in the supervised process.
Processes resolve resources (i.e. discover the PIDs of services in the system) by sending their supervisor a message.
The supervisor process is inherited by spawned child processes.

Each process has a privilege level of "driver", "privileged", or "unprivileged".
Unprivileged processes cannot send messages to other processes outside their supervisor's children.
Privileged processes can send messages to other processes outside their supervisor's children, but not outside their supervisor's supervisor's children.
A driver process can send messages to any process in the system.
Processes inherit the privilege level of their parent, unless their parent gives them a lower privilege level when spawned.

Supervisor processes and the privilege level system enable the creation of new resource scopes, where access to the rest of the system is totally mediated via the supervisor.
This is similar to containers, although technically much more flexible.

### Threads
A thread is a single path of execution in a process, and has its own:

- program counter/CPU state
- stack
- message queue
- state: running, waiting for message

Threads are scheduled by the kernel for execution on the available CPUs in the system.
Each thread has a unique ID. Thread IDs start from 1.
A single thread in each process is designated as the receiver thread for the process, and will receive messages from other processes who send messages to its process without a thread ID. By default, this is the main thread.

## Memory
Each process has its own virtual address space managed by the kernel.
When a process is created, the address space contains the loaded executable binary, the stack, and any initial parameters.
All processes can request new pages of RAM from the kernel to be mapped into their address space for heap purposes.

The Rust borrowing idea is extended to interprocess shared memory - a memory "loan".
Loans can either be shared and read-only (like a `&T`) or exclusive and read-write (like a `&mut T`).
A loan consists of the base address in the loaning process and the number of pages to be loaned.
The loan's extent must be an whole number of pages.
Driver processes can also request a loan from the kernel for an arbitrary region of physical addresses.

In addition to loans, processes can move memory from their own process to another process.

The kernel's own virtual memory is identity mapped to cover the whole range of physical memory.

## Messages
The kernel distributes messages between threads.
Messages consist of 64-byte blocks, and can be a maximum of 16 blocks long (1024 bytes).
Messages must be 8-byte aligned.
Messages contain:

- The process and thread ID of the sender. The thread ID is optional.
- The number of memory operations contained in the message.
- Flags indicating if it should be deleted from the thread's receive queue yet
- The number of blocks total used by the message
- Optionally, a memory loan or move that can be accepted by the receiver
- Message payload data to be interpreted by the receiver

Messages can be sent to a process' designated receiver thread without knowing the thread ID by leaving the thread ID unspecified.

The kernel must store messages that are in transit, having been sent but not yet received.
To do this, the kernel loans, for each thread, a region of memory to hold received messages for that thread.
The process does not actually need to know about this loan, because it receives the necessary slices from the `receive` system call.
Threads must mark the messages as read/deletable after they are done with them so the kernel can reuse the space.

## Boot Process
The kernel boot process looks something like:

- Parse the device tree blob and kernel arguments from U-boot to determine the hardware configuration
- Initialize core devices
    - CPU
    - Debug logging via UART
    - Memory
        - page tables
        - allocator
    - Interrupt controller and interrupt handlers
    - Timers
    - Thread scheduler
- Locate and parse the initramfs blob
- Load the `init` process from the initramfs and spawn it. The `init` process is loaned the device tree blob and initramfs blob, and starts with 'driver' permissions.
- Start the thread scheduler


# Interfaces
The kernel's interface is primarily the system call interface. Additionally, the kernel processes some configuration provided by the firmware via the device tree blob.

## Devicetree Blob
See the [Devicetree Specification](https://github.com/devicetree-org/devicetree-specification) for more details.
The kernel aims to interpret values in the blob as defined by the standard wherever possible to discover the devices present in the system.

### `/chosen/`
See Section 3.6 of the specification for more details.

This node may contain a kernel "command line" value in the `bootargs` property.
This value will be parsed as JSON and may contain the following keys:

- `init_exec_name`: filename of the init executable.
- `max_ihvm_cycles`: maximum number of cycles allowed for an interrupt handler function.

This node may also contain a `stdout-path` property. If present, this device will be the first choice for output from the kernel's debug logger.

## System Calls
The primary user space interface for the kernel is system calls.
System calls are made using the normal Aarch64 system call calling convention.
All system calls return zero on success, and an error code on failure. Any other outputs are returned via pointers.

TODO: should we use the immediate system call instruction value or pass the system call number via a register (like Linux?).
TODO: describe structures passed as arguments.

There should be a crate that provides nice definitions for each system call, and also defines the various types used and any useful operations on those types.

(Notational note: we use the `*mut [T]` notation to indicate that there is a `*mut T` that actually has more than one `T` in an array.)

### `send`
The `send` system call allows a process to send a message to another process.
The kernel will inspect the message header and automatically process any associated memory operations while it generates the header on the receiver side.
The message body will be copied to the receiver.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `msg`      | `*const [MessageBlock]`| Pointer to the start of memory in user space that contains the message. |
| `len`      | u8                   | Number of blocks the message contains total. |
| `msg_id`   | `*mut MessageId`     | If non-null, writes the unique ID of this message if it is successfully sent. Otherwise the value is preserved. |
| `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |

#### Flags
The `send` call accepts the following flags:

| Name           | Description                              |
|----------------|------------------------------------------|

#### Errors
- `NotFound`: the process/thread ID was unknown to the system.
- `BadFormat`: the message header was incorrectly formatted.
- `InboxFull`: the receiving process has too many queued messages and cannot receive the message.
- `InvalidLength`: the length of the message is invalid, i.e. `len` is not in `1..=16`.
- `InvalidFlags`: an unknown or invalid flag combination was passed.
- `InvalidPointer`: the message pointer was null or invalid.

#### Types

A `MessageBlock` is basically a `[u8; 64]`. The first block in the message must contain the message header.

### `receive`
The `receive` system call allows a process to receive a message from another process.
By default, loans are automatically applied if attached, and their details relative to the receiver will be present in the received message header.
The pointer returned by `receive` is valid until the message is marked for deletion.

This call will by default set the thread to a waiting state if there are no messages.
The thread will resume its running state when it receives a message.
This can be disabled with the `Nonblocking` flag, which will return `WouldBlock` as an error instead if there are no messages.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `msg`      | `*mut *mut [MessageBlock]`| Writes the pointer to the received message data here. |
| `len`      | `*mut u8`            | Writes the number of blocks the message contains total. |
| `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |

#### Flags
The `receive` call accepts the following flags:

| Name           | Description                              |
|----------------|------------------------------------------|
| `Nonblocking`  | Causes the kernel to return the `WouldBlock` error if there are no messages instead of pausing the thread. |
| `DenyMemoryTransfer` | Causes the kernel to ignore any memory operations contained in the received message. |

#### Errors
- `WouldBlock`: returned in non-blocking mode if there are no messages to receive.
- `InvalidFlags`: an unknown or invalid flag combination was passed.
- `InvalidPointer`: the message pointer or length pointer was null or invalid.

### `read_env_value`
Reads a value from the kernel about the current process environment.
Unlike all other system calls, because this call is infallible, the value to be read is returned from the call instead of an error.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `value_to_read`      | enum | The value to read from the kernel (see the `Values` section). |

#### Values
- `CurrentProcessId`: the process ID of the calling process.
- `CurrentThreadId`: the thread ID of the calling process.
- `DesignatedReceiverThreadId`: the thread ID of the calling process' designated receiver thread.
- `CurrentSupervisorId`: the process ID of the supervisor process for the calling process.
- `PageSizeInBytes`: the number of bytes per page of memory.

### `spawn_process`
Creates a new process. The calling process will become the parent process.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `image`    | `*const ProcessImage` | Describes the image that will be loaded as the process' initial memory. |
| `options`  | `*const ProcessSpawnOptions` | Optional parameters for spawining a process. If null, defaults are applied for all options. |
| `child_pid`| `*mut Process ID`    | If non-null, this pointer is the destination for the new process' ID. |
| `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |

#### Types
- `ProcessImage`

    Describes the image for the process as an array of segments.
    A segment consists of a slice of memory (in the calling process), page mapping attributes, and a base address and length in the new process' address space.
    The kernel copies each segment from the calling process into the new process, mapping the segment as directed.
    Segments can have the following page mapping attributes: read-only, read-write, and read-execute.
    If the segment's destination length is greater than the source length, then the rest of the segment will be zeroed.
    The process image also specifies the address where the main thread will start executing.
    It is an error to provide an image with overlapping segments or segments that are not page aligned.
    Segment lengths will be rounded to the next nearest page.

- `ProcessSpawnOptions`

    Describes the following additional options for creating processes:

    + New privilege level for the child, which must be equal to or below that of the caller
    + The supervisor PID for the child

#### Flags
| Name           | Description                              |
|----------------|------------------------------------------|
| IgnoreExit     | Skips sending the parent a message when the newly spawned process exits. |

#### Errors
- `OutOfMemory`: the system does not have enough memory to create the new process.
- `BadFormat`: the process image is invalid.
- `InvalidPointer`: a pointer was invalid or unexpectedly null.
- `InvalidFlags`: an unknown or invalid flag combination was passed.

### `kill_process`
Kills a process, causing it to exit with a fault.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `pid` |  Process ID   | The ID of the process to kill. |

### `exit_current_thread`
Exit the current thread, causing it to stop executing and allowing its resources to be cleaned up.
If this is the last thread in its process, then the process itself will exit with the same exit code.
This function does not return to the caller.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `exit_code` |  u32   | Code to return to the parent indicating the reason for exiting. The value 0 indicates success. |


### `spawn_thread`
Spawn a new thread in the current process.
This function also allocates new memory for the stack and inbox associated with the thread.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `entry` | function pointer | The entry point function for the thread. |
| `stack_size` | usize | Size in pages for the new stack allocated for the thread. |
| `inbox_size` | usize | Size in pages for the new message inbox allocated for the thread. |
| `user_data`  | `*mut ()` | This value is passed verbatim to the entry point function. |
| `thread_id`  | `*mut Thread ID` | Output for the thread ID assigned to the newly created thread. |
| `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |

#### Flags
The `spawn_thread` call accepts the following flags:

| Name           | Description                              |
|----------------|------------------------------------------|

#### Errors
- `OutOfMemory`: the system does not have enough memory to create the new thread.
- `InvalidLength`: the stack or inbox size is too small.
- `InvalidFlags`: an unknown or invalid flag combination was passed.
- `InvalidPointer`: the entry pointer was null or invalid.


### `set_designated_receiver`
Designates a thread in the current process as the thread which will receive messages from other processes who do not specify a thread ID.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `tid`      | Thread ID            | The ID of the thread to designate. |

#### Errors
- `NotFound`: the thread ID was unknown to the system.

### `allocate_heap_pages`
Allocates new system memory, mapping it into the current process' address space.
The contents of the memory are undefined.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `size` | usize | The number of pages to allocate. |
| `dest_ptr` | `*mut *mut ()` | Pointer to location to write the address of the new allocation. |
| `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |

#### Flags
The `allocate_heap_pages` call accepts the following flags:

| Name           | Description                              |
|----------------|------------------------------------------|

#### Errors
- `OutOfMemory`: the system does not have enough memory to make the allocation.
- `InvalidLength`: the size of the allocation is invalid.
- `InvalidFlags`: an unknown or invalid flag combination was passed.
- `InvalidPointer`: the destination pointer was null or invalid.

### `free_heap_pages`
Frees memory previously allocated by `allocate_heap_pages` from the process' address space, allowing another process to use it.
The base address pointer is invalid to access after calling this function.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `ptr` | `*mut ()` | Pointer to the base address of the allocation. |
| `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |

#### Flags
The `free_heap_pages` call accepts the following flags:

| Name           | Description                              |
|----------------|------------------------------------------|

#### Errors
- `InvalidFlags`: an unknown or invalid flag combination was passed.
- `InvalidPointer`: the base address pointer was null or invalid.


### `driver_request_address_region`
*This system call is allowed only for processes with the `driver` role.
Any other processes which call this function will exit with a fault.*

Creates a memory loan from the kernel for a region of physical address space.
This region must be **outside** of the addresses mapped to RAM to preserve the integrity of loans.
The driver is responsible for ensuring that access to these memory regions is safe.
Only one driver can request any address at a time.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `base_address` | usize | The physical base address of the region. |
| `size` | usize | The number of pages in the region. |
| `dest_ptr` | `*mut *mut ()` | Pointer to location to write the virtual address of the region in the calling process' address space. |
| `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |

#### Flags
The `driver_request_address_region` call accepts the following flags:

| Name           | Description                              |
|----------------|------------------------------------------|
| EnableCache    | By default, the mapping created will disable caching for the region. This will allow caching to take place. |

#### Errors
- `OutOfBounds`: the physical base address is in an invalid region, like RAM or other invalid physical addresses.
- `InUse`: the region has already been requested by a different driver.
- `InvalidLength`: the size of the region is invalid.
- `InvalidFlags`: an unknown or invalid flag combination was passed.
- `InvalidPointer`: the destination pointer was null or invalid.

### `driver_release_address_region`
*This system call is allowed only for processes with the `driver` role.
Any other processes which call this function will exit with a fault.*

Releases an address range previously loaned to the current process.
The virtual base address pointer for the region is invalid to access after calling this function.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `ptr` | `*mut ()` | Pointer to the base address of the loaned region. |
| `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |

#### Flags
The `driver_release_address_region` call accepts the following flags:

| Name           | Description                              |
|----------------|------------------------------------------|

#### Errors
- `InvalidFlags`: an unknown or invalid flag combination was passed.
- `InvalidPointer`: the base address pointer was null or invalid.

### `driver_register_interrupt`
*This system call is allowed only for processes with the `driver` role.
Any other processes which call this function will exit with a fault.*

Registers a handler program with the kernel to handle when the specified hardware interrupt occurs.
More than one driver may register for the same interrupt, and all of them will be executed.

Interrupt handler programs are encoded in the Interrupt Handler Virtual Machine (IHVM) bytecode format, described in (`ihvm.md`)[./ihvm.md].
If the handler panics, then a message will be sent to the driver containing the handler ID and panic error code.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `desc`     | `*const InterruptDesc` | Description of the interrupt to register for. |
| `handler_pgrm` | `*const InterruptHandlerProgram` | The program to execute to handle an interrupt. |
| `handler_id` | `*mut handler ID` | Returns the ID of the handler. |
| `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |

#### Flags
The `driver_register_interrupt` call accepts the following flags:

| Name           | Description                              |
|----------------|------------------------------------------|

#### Errors
- `NotFound`: an unknown or invalid thread ID was given for the receiver.
- `InvalidFlags`: an unknown or invalid flag combination was passed.
- `BadFormat`: the interrupt description or program is invalid.
- `InvalidPointer`: the description or program pointer was null or invalid.

#### Types

- `InterruptDesc`: describes a hardware interrupt
- `InterruptHandlerProgram`: describes the interrupt handler program that will be executed. This includes the bytecode and the memory regions in the driver's address space that will be accessible, per the IHVM spec.

### `driver_unregister_interrupt`
*This system call is allowed only for processes with the `driver` role.
Any other processes which call this function will exit with a fault.*

Unregisters a previously registered interrupt handler. The handler will no longer run on interrupts after this call.

#### Arguments
| Name       | Type                 | Notes                            |
|------------|----------------------|----------------------------------|
| `handler_id` | handler ID | The ID of the handler returned from `driver_register_interrupt`. |
| `flags`    | bitflag              | Options flags for this system call (see the `Flags` section). |

#### Flags
The `driver_unregister_interrupt` call accepts the following flags:

| Name           | Description                              |
|----------------|------------------------------------------|

#### Errors
- `NotFound`: the specified handler was not found.
- `InvalidFlags`: an unknown or invalid flag combination was passed.

### Errors
This table collects all possible errors returned from system calls.

| Error            | Description                                                                                          |
|------------------|------------------------------------------------------------------------------------------------------|
| `NotFound`       | The specified process, thread, or handler ID was unknown or not found in the system.                 |
| `BadFormat`      | The provided data was incorrectly formatted (e.g., message header, process image, interrupt data).   |
| `InboxFull`      | The receiving process's message queue is full, and it cannot accept additional messages.             |
| `InvalidLength`  | The specified length was invalid, out of bounds, or not in the acceptable range.                     |
| `InvalidFlags`   | An unknown, unsupported, or invalid combination of flags was passed.                                 |
| `InvalidPointer` | A pointer provided was null, invalid, or otherwise could not be used as expected.                    |
| `OutOfMemory`    | The system does not have enough available memory to complete the requested operation.                |
| `OutOfBounds`    | The specified address or memory region was outside the allowed range or otherwise invalid.           |
| `WouldBlock`     | The operation would block the calling thread, but non-blocking mode was specified.                   |
| `InUse`          | The requested resource or memory region is already in use by another process or driver.              |


## Debug Logging
The kernel will print its logs to the device indicated in the device tree, or the default platform debug device if known.
This should be a simple UART.

# Implementation Thoughts
This section is just some thoughts about implementation details. Things may or may not turn out like this.

## Messages
Messages should be short enough to be copied in a few instructions.
A single `LD1` instruction can load up to 64 bytes (using four actual loads), which motivates the message block size.

## Device Driver Servers
A typical device driver server would be spawned as a 'driver' type process by the `init` process.
The driver would first request loans from the kernel or its lower-level driver, set up interrupts with the kernel, and then initialize the device.
The driver then listens for requests from clients, and handles them using the device. Ideally most actual data transfers happen using loans.