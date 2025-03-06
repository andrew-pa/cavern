# Bootstrap Service
The "egg" bootstrap service is the first spawned process and starts the rest of the system.
This requires it to have a few somewhat disjoint responsibilities:
- providing a service to interact with the initial RAM disk passed from the kernel as a file system
- spawning the root resource registry process, root supervisor process and log redistributor
- starting various core drivers based on the device tree blob passed from the kernel

## Kernel Interface
The egg interfaces directly with the kernel due to being the first process spawned.
The kernel must map the initial RAM disk image and device tree blob into its address space, using a read-only mapping.
The egg expects before doing anything to receive a message from the kernel containing:
- the address/length of the initial RAM disk in its virtual address space
- the address/length of the device tree blob in its virtual address space
