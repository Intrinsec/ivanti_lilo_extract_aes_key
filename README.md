# ivanti_lilo_extract_aes_key

This tool will try to find the AES key decoding routine located in the "loop_setup_root" function of Ivanti Kernels based on LILO. It will then extract the key and decode it to display it in a format compatible with the lilo-pulse-secure-decrypt tool. Learn more at https://www.intrinsec.com/ivanti-auto-aes-keys-recovery/

## Building

Verify that RUST is properly installed on your system by typing following command.

``` bash
rustup show
```

The command should display the version of Rust and the default toolchain being used.

You can then compile the tool with the following command.

```bash
cargo build --release
```

## Usage

This tool only take 1 parameter, an Ivanti Kernel file based on LILO which has been decompressed with https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux

```bash
.\ivanti_lilo_extract_aes_key.exe .\kernel_decompressed
Linux Kernel version found: "Linux version 2.6.32-000XX-XXXXXX-dirty (slt_ec_builder@lxc-linux64-0001-scl6_4_R3_1_9-pulse6_4R3_1_9) (gcc version 4.7.0 20120302 (Red Hat 4.7.0-0.11.1) (GCC) ) #1 SMP Sun Jan 28 11:46:33 EST 2024"
Pattern search result:
- Pattern: "8B 35 ? ? ? ? 8B 0D ? ? ? ? 48 89 DF"
- Found at offset: "00000000004D5AE3"
- Virtual address: "FFFFFFFF812D5AE3"

AES KEY = [e8, 6e, 2f, 77, ac, 42, 2f, 65, XX, XX, XX, XX, XX, XX, XX, XX]

You can use the lilo-pulse-secure-decrypt tool to decrypt your disk partitions, adding the line below to the keys.c file before compiling.

{ .kernel_version = "2.6.32-000XX-XXXXXXX-dirty", .key = {0xE8, 0x6E, 0x2F, 0x77, 0xAC, 0x42, 0x2F, 0x65, 0xXX, 0xXX, 0xXX, 0xXX, 0xXX, 0xXX, 0xXX, 0xXX} },
```

## Decryption

```bash
git clone https://github.com/NorthwaveSecurity/lilo-pulse-secure-decrypt
```

Add extracted AES key to `keys.c` file and build.

```bash
make
```

You should now be able to decrypt encrypted partitions with the following command.

```bash
./dsdecrypt /path/to/encrypted_partition.img decrypted_partition.img
```

## External Ressources

https://github.com/NorthwaveSecurity/lilo-pulse-secure-decrypt
