# Supervisor Service
The supervisor service is responsible for spawning, monitoring and respawning processes.

## Model
The supervisor watches a set of processes.
When a process exits, the supervisor executes one of the following policies:
- ignores the exit
- restarts the process, optionally up to a limit and with a configurable delay/debounce
- exits itself, after making sure all other monitored processes have been killed
- kills and restarts all supervised processes, up to a limit of counts set globally for the supervisor

Different policies can be provided for different process exit reasons, both for all monitored processes and for individual processes.

(TODO: supervisors could also provide a health check/heartbeat message)

## RPC Methods
### Configure
The Configure method can be executed once, before any processes are spawned.
This method allows the caller to configure the default process exit policy.
It also optionally allows the caller to specify a file to load and interpret, representing processes that should be spawned. See the 'File Format' section.

### Spawn
The Spawn method allows new processes to be spawned dynamically that will be monitored by this supervisor.
Proess specific exit policy can also be configured.
The supervisor takes care of reading and interpreting the executable from the file system.

### List Monitored Processes
This method returns a list of the processes monitored by this supervisor.

### Status
The Status method retrieves the current status of a process by id according to the supervisor.

## File Format
...
