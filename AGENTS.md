# Agent Guidelines for Cavern Repository

## Overview
This repo contains a Rust-based microkernel named **Cavern** along with
support crates, services and documentation. The project uses a workspace with
multiple crates. Below is a high level outline of the top level directories:

- `kernel/` – the microkernel binary. Contains the entry point and hardware
  specific code. Built for `aarch64-unknown-none`.
- `kernel_core/` – policies, data structures and algorithms for the kernel that
  can be unit tested on the host.
- `kernel_api/` – public kernel API defining system calls and types shared with
  user space.
- `device_tree/` – parser for FDT/Devicetree blobs used during boot.
- `user_core/` – utilities and runtime support for user space services when the
  standard library is not available.
- `services/` – standalone user space services such as:
  - `egg/` – bootstrap service that starts the rest of the system.
  - `registry/` – resource registry service.
  - `check-syscalls/` – integration test program executed by the kernel in CI.
- `spec/` – design documents for the OS and its components.
- `initramfs_template/` – files included in the initial ramdisk image.
- `vendor/` – external submodules (currently U‑Boot).
- `.github/` – CI configuration; mirrors the commands in `justfile`.

## Contribution and Style
- The codebase is written in Rust 2021/2024 edition and mostly `no_std`.
- Formatting and linting are enforced. Use `cargo fmt` and `cargo clippy` via the
  provided `just` tasks.
- All public items should have documentation comments. Missing docs cause
  clippy errors.
- Follow the existing 4‑space indentation and keep code readable and modular.
- When adding new features, update or create relevant documentation under `spec/`
  if behaviour or interfaces change.

### Commit and PR etiquette
- Keep commits focused and descriptive.
- PR bodies should contain a **Summary** of the changes with inline citations to
  modified files and a **Testing** section describing the checks that were run.
- If any tests fail due to missing dependencies or network restrictions mention
  the provided disclaimer.

## Build and Validation
The repository relies on the [just](https://just.systems/) command runner. The
most common tasks are:

```bash
just fmt            # Format the code
just check          # Format check, type check and clippy lint
just test           # Run host based unit tests
just build          # Build all crates for aarch64
just make-images    # Build kernel and initrd images
just run-qemu       # Boot the system under QEMU
```
Relevant excerpts from `justfile`:
```
18  fmt cargo_args="":
19      cargo fmt
21  # Check formatting, types and lints.
22  check cargo_args="" clippy_args="":
23      cargo fmt --check {{cargo_args}}
24      cargo check --target aarch64-unknown-none --all-features {{cargo_args}}
25      cargo clippy --target aarch64-unknown-none --all-features {{cargo_args}} -- -Dmissing_docs -Dclippy::all -Wclippy::pedantic {{clippy_args}}
33  # Test Rust crates that are testable on the host.
34  test cargo_args="":
35      cargo test -p kernel_core -p device_tree --target {{host_target_triple}} {{cargo_args}}
```

Before committing, always run:
1. `just fmt`
2. `just check`
3. `just test`

These match the CI steps defined in `.github/workflows/build.yaml`.

## Using the Repository
- Start exploring in `spec/` for high level design. Kernel specific
  documentation lives in `spec/kernel.md` and service docs are under
  `spec/services/`.
- The kernel entry point is in `kernel/src/main.rs`. Most logic lives in
  `kernel_core/`.
- When extending services or adding new ones, use `user_core` utilities for
  heap allocation, RPC and task management.
- Integration tests (e.g. `check-syscalls`) are run via QEMU with
  `just run-kernel-check`.

Follow these notes to keep contributions consistent and maintainable.
