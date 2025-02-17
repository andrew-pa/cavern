add-symbol-file target/aarch64-unknown-none/debug/kernel
add-symbol-file target/aarch64-unknown-none/debug/init
target remote localhost:3433
break init::_start
continue
