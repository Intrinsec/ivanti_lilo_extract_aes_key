use std::fmt;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::str;
use goblin::elf::Elf;
use iced_x86::{Decoder, Register, DecoderOptions, Instruction};
use patternscanner::PatternScannerBuilder;
use clap::Parser;

macro_rules! debug_println {
    ($($arg:tt)*) => (if ::std::cfg!(debug_assertions) { ::std::println!($($arg)*); })
}

const EXAMPLE_CODE_BITNESS: u32 = 64;
const EXAMPLE_CODE_RIP: u64 = 0xFFFF_FFFF_8100_0000;
struct BytesWrapper([u8; 4]);

impl fmt::Display for BytesWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes_string = self.0.iter()
            .map(|byte| format!("{:02X}", byte))
            .collect::<Vec<_>>()
            .join(" ");
        write!(f, "{}", bytes_string)
    }
}

#[derive(Parser)]
struct Cli {
    /// The path to the kernel file (ELF), use extract-vmlinux to decompress your kernel file before running this tool.
    path: std::path::PathBuf,
}

fn swap_endianness(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(bytes.chunks_exact(4)
         .flat_map(|chunk| {
             let mut swapped_chunk = [0; 4];
             swapped_chunk.copy_from_slice(&chunk);
             swapped_chunk.reverse();
             swapped_chunk.to_vec()
         })
         .collect())
}

fn file_offset_to_virtual_address(elf: &Elf, file_offset: u64) ->  Result<u64, Box<dyn std::error::Error>> {
    for header in &elf.program_headers {
        if header.p_type == goblin::elf::program_header::PT_LOAD && file_offset >= header.p_offset && file_offset < (header.p_offset + header.p_filesz) {
            return Ok(header.p_vaddr + (file_offset - header.p_offset))
        }
    }
    Err("Error: Cannot translate file offset to virtual address !")?
}

fn virtual_address_to_file_offset(elf: &Elf, virtual_address: u64) ->  Result<u64, Box<dyn std::error::Error>>  {
    for header in &elf.program_headers {
        if header.p_type == goblin::elf::program_header::PT_LOAD &&
            virtual_address >= header.p_vaddr && 
            virtual_address < (header.p_vaddr + header.p_memsz)
        {
            let file_offset = header.p_offset + (virtual_address - header.p_vaddr);
            return Ok(file_offset)
            }
    }
    Err("Error: Cannot translate virtual address to file offset !")?
}

fn find_pattern(kernel_file_buffer: &Vec<u8>, pattern: &str ) ->  Result<u64, Box<dyn std::error::Error>> {
    let result = PatternScannerBuilder::builder()
    .with_bytes(kernel_file_buffer)
    .build()
    .scan(pattern);
    match result {
         Ok(Some(value)) => return Ok(value as u64),
         _ =>  Err("Error: Could no find the pattern !")?
     }
}

fn find_aes_key(file_buffer :&Vec<u8>, elf: &Elf, file_offset: u64, va: u64) -> Result<(Vec<(iced_x86::Register, u64)>, Vec<(iced_x86::Register, u32)>), Box<dyn std::error::Error>>{
    let mut decoder = Decoder::with_ip(EXAMPLE_CODE_BITNESS, &file_buffer, EXAMPLE_CODE_RIP + file_offset as u64, DecoderOptions::NONE);
    decoder.set_position(file_offset as usize)?;
    decoder.set_ip(va);
    let mut instr = Instruction::default();
    let mut aes_key_mov_addr: Vec<( Register, u64) > = Vec::new();
    let mut xor_key: Vec<( Register, u32) > = Vec::new();
    let max_instr = 40;
    let mut instr_ct = 0;
    while decoder.can_decode() && instr_ct <= max_instr{
        decoder.decode_out(&mut instr);
        if instr.op_code().mnemonic() == iced_x86::Mnemonic::Mov {
            match instr.try_op_register(0) {
                Ok(op0) => {
                    if op0 == Register::ESI || op0 == Register::ECX || op0 == Register::EDX || op0 == Register::EAX {
                        debug_println!("Address : {:016X}, Register: {:?}, Mov address: 0x{:X}", instr.ip(), op0, instr.memory_displacement64());
                        aes_key_mov_addr.push((op0, virtual_address_to_file_offset(&elf, instr.memory_displacement64())?));  
                    }
                }
                Err(err) => {
                    eprintln!("Decoding error : {:?}", err);
                }
            }
        }

        if instr.op_code().mnemonic() == iced_x86::Mnemonic::Xor {
            match instr.try_op_register(0) {
                Ok(op0) => {
                    if op0 == Register::ESI || op0 == Register::ECX || op0 == Register::EDX || op0 == Register::EAX {
                        debug_println!("Address : {:016X}, Register: {:?}, Xor value : 0x{:X}", instr.ip(), op0, instr.immediate32());
                        xor_key.push((op0, instr.immediate32()));
                    }
                }
                Err(err) => {
                    eprintln!("Decoding error : {:?}", err);
                }
            }
        }
        instr.set_next_ip(instr.next_ip() + instr.len() as u64);
        if aes_key_mov_addr.len() == 4 && xor_key.len() == 4{
            return Ok((aes_key_mov_addr, xor_key));
        }
        instr_ct += 1;
    }
    Err("Error: Cannot find AES key !")?
}

fn read_xored_aes_key(mut kernel_file: &File, key_offset: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>>{
    let mut xored_aes_key = [0; 16];
    kernel_file.seek(io::SeekFrom::Start(key_offset))?;
    kernel_file.read_exact(&mut xored_aes_key)?;
    Ok(xored_aes_key.to_vec())
}

fn xor_value_to_le_bytes(xor_value :&Vec<(Register, u32)>) -> Result<Vec<u8>, Box<dyn std::error::Error>>{
    let mut xor_key: Vec<u8> = Vec::new();
    for entry in xor_value {
        let bytes: [u8; 4] = entry.1.to_le_bytes();
        xor_key.extend_from_slice(&bytes);
    }
    Ok(xor_key)
}

fn do_xor(key: &Vec<u8>, xor_key: &Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>>{
    let aes_key: Vec<u8> =  key
        .iter()
        .zip(xor_key.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    Ok(aes_key)
}

fn search_linux_kernel_version_in_elf(elf: &Elf, kernel_file_buffer: &[u8], search_string: &str) -> Option<String> {
    for section in &elf.section_headers {
        if section.sh_type != goblin::elf::section_header::SHT_PROGBITS {
            continue;
        }

        let section_name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("Unknown");
        if !section_name.starts_with(".rodata") {
            continue;
        }

        let section_data = &kernel_file_buffer[section.sh_offset as usize..(section.sh_offset + section.sh_size) as usize];

        if let Some(index) = section_data.windows(search_string.len()).position(|window| window == search_string.as_bytes()) {
            let found_string = &section_data[index..];
            let line_end = found_string.iter().position(|&c| c == b'\n').unwrap_or(found_string.len());
            let line = std::str::from_utf8(&found_string[..line_end]).unwrap_or("");
            println!("Linux Kernel version found: {:#?}", line.to_string());
            return Some(line.split_whitespace().nth(2).unwrap_or_default().to_string());
        }
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open Kernel file, read it as Vec<u8> and parse it with goblin
    let args = Cli::parse();
    let kernel_file: File = File::open(&args.path).expect("Cannot open file !");
    let kernel_file_buffer = fs::read(&args.path).expect("Cannot open file !");
    let elf = match Elf::parse(&kernel_file_buffer) {
        Ok(elf) => elf,
        Err(error) => panic!("Error parsing the file, is it a decompressed Linux kernel? {:?}", error)
    };

    // Search for Linux Kernel version
    let kernel_version_short = search_linux_kernel_version_in_elf(&elf, &kernel_file_buffer, "Linux version").unwrap_or("Kernel version not found".to_string());
    
    // Search for the AES key construction pattern ("8B 35 ? ? ? ? 8B 0D ? ? ? ? 48 89 DF") in the loop_setup_root function
    // Pattern should match the file offset of the instruction "mov     esi, cs:dword_FFFFFFFF815C44A0" 
    // .text:FFFFFFFF812D5AE3  mov     esi, cs:dword_FFFFFFFF815C44A0 
    // .text:FFFFFFFF812D5AE9  mov     ecx, cs:dword_FFFFFFFF815C44A4
    // .text:FFFFFFFF812D5AEF  mov     rdi, rbx
    // .text:FFFFFFFF812D5AF2  mov     edx, cs:dword_FFFFFFFF815C44A8
    // .text:FFFFFFFF812D5AF8  mov     eax, cs:dword_FFFFFFFF815C44AC
    // .text:FFFFFFFF812D5AFE  mov     dword ptr [rbx+0F8h], 0FFFFFFFFh
    // .text:FFFFFFFF812D5B08  mov     dword ptr [rbx+0C8h], 10h
    // .text:FFFFFFFF812D5B12  xor     esi, 99ED2BF2h 
    // .text:FFFFFFFF812D5B18  xor     ecx, 0AEEF41FEh
    // .text:FFFFFFFF812D5B1E  mov     [rbp+var_C8], 10h
    // .text:FFFFFFFF812D5B28  mov     [rbp+var_40], esi
    // .text:FFFFFFFF812D5B2B  lea     rsi, [rbp+var_F8]
    // .text:FFFFFFFF812D5B32  xor     edx, 141058C7h
    // .text:FFFFFFFF812D5B38  xor     eax, 0D2ED180Eh
    
    let pattern_1_loop_setup_root = "8B 35 ? ? ? ? 8B 0D ? ? ? ? 48 89 DF";
    let pattern_file_offset = find_pattern(&kernel_file_buffer, &pattern_1_loop_setup_root).expect("Cannot find pattern to loop_setup_root function :(");
    let pattern_1_va = file_offset_to_virtual_address(&elf, pattern_file_offset).expect("Cannot convert file offset to virtual address.");
    let raw_key = find_aes_key(&kernel_file_buffer, &elf, pattern_file_offset, pattern_1_va).expect("Key not found !");

    // Check addresses
    // The addresses of the 4 dwords should be consecutive.
    // 0xFFFFFFFF815B9000
    // 0xFFFFFFFF815B9004
    // 0xFFFFFFFF815B9008
    // 0xFFFFFFFF815B900C

    let xored_aes_key_addr;
    if let (Some(first_key), Some(last_key)) = (raw_key.0.get(0), raw_key.0.get(3)) {
        if first_key.1 + 0xC != last_key.1 {
            panic!("Key not found !");
        } else {
            xored_aes_key_addr = first_key.1;
            let xored_aes_key = read_xored_aes_key(&kernel_file, xored_aes_key_addr).expect("Failed to recover AES key !");
            debug_println!("AES KEY file offset : {:016X}", xored_aes_key_addr);
            debug_println!("XORED KEY :{:x?}", xored_aes_key);
            let xor_key = xor_value_to_le_bytes(&raw_key.1)?;
            debug_println!("XOR KEY :{:x?}", xor_key);
            let aes_key = do_xor(&xored_aes_key, &xor_key)?;
            debug_println!("AES KEY :{:x?}", aes_key);
            let aes_key_swap_endianness = swap_endianness(&aes_key)?;

            // Print results
            println!("Pattern search result:");
            println!("- Pattern: {}", pattern_1_loop_setup_root);
            println!("- Found at offset: {:016X}", pattern_file_offset);
            println!("- Virtual address: {:016X}", pattern_1_va);
            println!("\r\nAES KEY = {:x?}", aes_key_swap_endianness);

            //Print to lilo-pulse-secure-decrypt dsdecrypt keys.c format 
            println!("\r\nYou can use the lilo-pulse-secure-decrypt tool to decrypt your disk partitions, adding the line below to the keys.c file before compiling.");
            println!("\r\n{{ .kernel_version = \"{}\", .key = {{{}}} }},", kernel_version_short, aes_key_swap_endianness.iter().map(|b| format!("0x{:02X}", b)).collect::<Vec<String>>().join(", "));
        }
    } else {
        panic!("Key not found !");
    }

    Ok(())

}