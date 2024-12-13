target_prefix := "aarch64-linux-gnu-"
build_profile := "debug"

out_dir := env("EH_OUTPUT_DIR", absolute_path("./.build"))
img_dir := out_dir / "image"
vendor_tool_dir := out_dir / "vendor"

host_target_triple := `rustc --version --verbose | grep "host" | awk '{print $2}'`

# Choose a task to run.
default:
    @just --choose

# Delete generated outputs.
clean:
    rm -rf {{out_dir}}

fmt cargo_args="":
    cargo fmt

# Check formatting, types and lints.
check cargo_args="" clippy_args="":
    cargo fmt --check {{cargo_args}}
    cargo check --target aarch64-unknown-none --all-features {{cargo_args}}
    cargo clippy --target aarch64-unknown-none --all-features {{cargo_args}} -- -Dmissing_docs -Dclippy::all -Wclippy::pedantic {{clippy_args}}

# Test Rust crates that are testable on the host.
test cargo_args="":
    cargo test -p kernel_core --target {{host_target_triple}} {{cargo_args}}

# Build Rust crates.
build cargo_args="":
    cargo build {{ if build_profile == "release" { "--release" } else { "" } }} --target aarch64-unknown-none {{cargo_args}}

mkimage_bin := vendor_tool_dir / "u-boot/tools/mkimage"

binary_path := "target/aarch64-unknown-none" / build_profile
kernel_load_addr := "41000000"
initrd_load_addr := "44000000"

# Create U-boot image for the kernel.
make-kernel-image kernel_elf_path=(binary_path / "kernel") mkimage_args="": build
    #!/bin/bash
    set -euxo pipefail
    mkdir -p {{img_dir}}
    if [ "{{img_dir / "kernel.img"}}" -nt "{{kernel_elf_path}}" ]; then
        echo "kernel image already up-to-date"
        exit 0
    fi
    flat_binary_path=$(mktemp -t kernel.XXXXXX.img)
    {{target_prefix}}objcopy -O binary {{kernel_elf_path}} $flat_binary_path
    {{mkimage_bin}} -A arm64 -O linux -T kernel -C none -a {{kernel_load_addr}} -e {{kernel_load_addr}} -n "cavern-kernel" -d $flat_binary_path {{mkimage_args}} {{img_dir / "kernel.img"}}
    rm $flat_binary_path

# Create U-boot image for the initial RAM disk archive
make-initrd-image mkimage_args="": build
    #!/bin/bash
    set -euxo pipefail
    mkdir -p {{img_dir}}
    archive_path=$(mktemp -t initrd.XXXXXX.tar)
    tar --format=ustar -cf $archive_path ./README.md
    {{mkimage_bin}} -A arm64 -O linux -T ramdisk -C none -a {{kernel_load_addr}} -n "cavern-initrd" -d $archive_path {{mkimage_args}} {{img_dir / "initrd.img"}}
    rm $archive_path

# Run the system in QEMU.
run-qemu qemu_args="-m 4G -smp 8" boot_args="{}": make-kernel-image
    #!/bin/sh
    set -euxo pipefail
    qemu-system-aarch64 \
        -machine virt -cpu cortex-a57 \
        -semihosting \
        -bios {{vendor_tool_dir / "u-boot/u-boot.bin"}} \
        -nographic \
        -drive if=none,file=fat:rw:{{img_dir}},id=kboot,format=raw \
        -device nvme,drive=kboot,serial=foo {{qemu_args}} \
    <<-END
        nvme scan
        fatload nvme 0 0x{{kernel_load_addr}} kernel.img
        fatload nvme 0 0x{{initrd_load_addr}} initrd.img
        env set bootargs '{{boot_args}}'
        bootm {{kernel_load_addr}} {{initrd_load_addr}} 40000000
    END

# Create an `asciinema` recording of booting the system in QEMU.
create-boot-video output_file="/tmp/bootvideo.cast" asciinema_args="--cols 160 --rows 40 --idle-time-limit 1" qemu_args="-m 4G -smp 8" boot_args="{}":
    asciinema rec --command='just run-qemu "{{qemu_args}}" "{{boot_args}}"' --title="cavern_boot@{{`git rev-parse --short=8 HEAD`}}" --overwrite {{asciinema_args}} {{output_file}}

make_bin := `which make`

# Build U-Boot image and tools.
build_u-boot:
    mkdir -p {{vendor_tool_dir / "u-boot"}}
    CROSS_COMPILE={{target_prefix}} {{make_bin}} -C ./vendor/u-boot O={{vendor_tool_dir / "u-boot"}} qemu_arm64_defconfig
    CROSS_COMPILE={{target_prefix}} {{make_bin}} -C ./vendor/u-boot O={{vendor_tool_dir / "u-boot"}} -j all
