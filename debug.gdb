add-symbol-file target/aarch64-unknown-none/debug/kernel
target remote localhost:3433
break kernel::kmain
break kernel::panic_handler
# break _start
break *0x41000000
#continue
