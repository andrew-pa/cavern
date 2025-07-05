add-symbol-file target/aarch64-unknown-none/debug/kernel
add-symbol-file target/aarch64-unknown-none/debug/check-syscalls
target remote localhost:3433
break check_syscalls::_start
continue
