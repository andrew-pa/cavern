# Bootstrap Service
The "egg" bootstrap service is the first spawned process and starts the rest of the system.
This requires it to have a few somewhat disjoint responsibilities:
- providing a service to interact with the initial RAM disk passed from the kernel as a file system
- spawning the root resource registry process, root supervisor process and log redistributor
- starting various core drivers based on the device tree blob passed from the kernel

## Initramfs Service
The "egg" service exposes a standard file system under `/volume/init` that provides access to the contents of the initial RAM disk image.
The disk image must be in `tar` format, specifically the `ustar` variant.

## Boot Sequence
1. Read configuration from initramfs
2. Spawn the root resource registry directly using the initramfs
3. Register the initramfs service with the registry
4. Spawn the root supervisor directly using the initramfs
5. Instruct the root supervisor to spawn the log redistributor
6. Visit the various nodes in the device tree and instruct the root supervisor to spawn the relevant driver processes
    - drivers should be identified using the "compatible" field
    - driver processes should receive their device tree blob node for initialization
7. Spawn the system supervisor as a child of the root supervisor and direct it to spawn other system services as specified in the configuration
8. Spawn the user/unprivilaged supervisor as a child of the root supervisor and direct it as specified in the configuration (this is like where you'd spawn the shell)

## Configuration
The configuration file contains the following information:
- path of resource registry, supervisor and log redistributor binaries in the initramfs
- list of core device drivers:
    - their paths in the initramfs
    - the set of devices they are compatible with
- path to configuration file for system service supervisor
- path to configuration file for user process supervisor
- any parameters for the log redistributor process

## Kernel Interface
The egg interfaces directly with the kernel due to being the first process spawned.
The kernel must map the initial RAM disk image and device tree blob into its address space, using a read-only mapping.
The egg expects before doing anything to receive a message from the kernel containing:
- the address/length of the initial RAM disk in its virtual address space
- the address/length of the device tree blob in its virtual address space

