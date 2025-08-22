use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use goblin::elf::Elf;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::sofixer::SoFixer;
use crate::utils::{MemoryMapping, SoInfo};

// Author: mrack <https://github.com/mrack>
pub struct SoDumper {
    target_pid: u32,
    target_name: String,
    output_dir: PathBuf,
    sofixer: SoFixer,
    auto_fix: bool,
}

impl SoDumper {
    pub fn new(target_pid: u32, target_name: String, output_dir: PathBuf) -> Result<Self> {
        let sofixer = SoFixer::new()?;
        Ok(Self {
            target_pid,
            target_name,
            output_dir,
            sofixer,
            auto_fix: true,
        })
    }

    pub fn extract_sofixer(&self) -> Result<()> {
        self.sofixer.extract()
    }

    fn get_solist_offset(&self) -> Result<u64> {
        let linker_path = "/system/bin/linker64";
        let mut file = File::open(linker_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let elf = Elf::parse(&buffer)?;

        for sym in elf.syms.iter() {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name.contains("__dl__ZL6solist") {
                    return Ok(sym.st_value);
                }
            }
        }

        Err(anyhow!("Could not find solist symbol in linker64"))
    }

    fn stop_process(&self) -> Result<()> {
        kill(Pid::from_raw(self.target_pid as i32), Signal::SIGSTOP)?;
        println!("[+] Process {} stopped", self.target_pid);
        Ok(())
    }

    fn continue_process(&self) -> Result<()> {
        kill(Pid::from_raw(self.target_pid as i32), Signal::SIGCONT)?;
        println!("[+] Process {} continued", self.target_pid);
        Ok(())
    }

    fn parse_proc_maps(&self) -> Result<Vec<MemoryMapping>> {
        let maps_path = format!("/proc/{}/maps", self.target_pid);
        let file = File::open(&maps_path)?;
        let reader = BufReader::new(file);
        let mut mappings = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 6 {
                let addr_range: Vec<&str> = parts[0].split('-').collect();
                let start = u64::from_str_radix(addr_range[0], 16)?;
                let end = u64::from_str_radix(addr_range[1], 16)?;
                let permissions = parts[1].to_string();
                let offset = u64::from_str_radix(parts[2], 16)?;
                let device = parts[3].to_string();
                let inode = parts[4].parse::<u64>()?;
                let pathname = if parts.len() > 5 {
                    parts[5].to_string()
                } else {
                    String::new()
                };

                mappings.push(MemoryMapping {
                    start,
                    end,
                    permissions,
                    offset,
                    device,
                    inode,
                    pathname,
                });
            }
        }

        Ok(mappings)
    }

    fn get_linker_base(&self) -> Result<u64> {
        let mappings = self.parse_proc_maps()?;

        for mapping in mappings {
            if mapping.pathname.contains("linker64") {
                return Ok(mapping.start);
            }
        }

        Err(anyhow!("Could not find linker64 in process maps"))
    }

    fn get_target_mapping(&self) -> Result<(u64, u64)> {
        let mappings = self.parse_proc_maps()?;
        let mut target_start = None;
        let mut target_end = None;

        for mapping in &mappings {
            if mapping.pathname.contains(&self.target_name) {
                if target_start.is_none() {
                    target_start = Some(mapping.start);
                }
                target_end = Some(mapping.end);
            }
        }

        match (target_start, target_end) {
            (Some(start), Some(end)) => {
                if start > 0x7fffffff {
                    Ok((start, end))
                } else {
                    Err(anyhow!("Target SO is 32-bit (base: {:#x}), only 64-bit SO files are supported. 32-bit SO files have base addresses below 0x80000000.", start))
                }
            }
            _ => Err(anyhow!(
                "Could not find target {} in process maps",
                self.target_name
            )),
        }
    }

    fn read_process_memory(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        let mem_path = format!("/proc/{}/mem", self.target_pid);
        let mut file = File::open(&mem_path)?;
        file.seek(SeekFrom::Start(address))?;

        let mut buffer = vec![0u8; size];
        file.read_exact(&mut buffer)?;

        Ok(buffer)
    }

    fn get_solist_head(&self, solist_addr: u64) -> Result<u64> {
        let data = self.read_process_memory(solist_addr, 8)?;
        let mut cursor = std::io::Cursor::new(data);
        let solist_head = cursor.read_u64::<LittleEndian>()?;

        println!("[*] solist head: {:#x}", solist_head);
        Ok(solist_head)
    }

    fn parse_soinfo(&self, soinfo_addr: u64) -> Result<SoInfo> {
        let data = self.read_process_memory(soinfo_addr, 256)?;

        const PTR_SIZE: usize = 8;
        const OFF_BASE: usize = 0x10;
        const OFF_SIZE: usize = 0x18;
        const OFF_NEXT: usize = 0x28;

        let mut cursor = std::io::Cursor::new(&data[OFF_BASE..OFF_BASE + PTR_SIZE]);
        let base = cursor.read_u64::<LittleEndian>()?;

        let mut cursor = std::io::Cursor::new(&data[OFF_SIZE..OFF_SIZE + PTR_SIZE]);
        let size = cursor.read_u64::<LittleEndian>()?;

        let mut cursor = std::io::Cursor::new(&data[OFF_NEXT..OFF_NEXT + PTR_SIZE]);
        let next = cursor.read_u64::<LittleEndian>()?;

        Ok(SoInfo { base, size, next })
    }

    fn find_target_soinfo(&self, solist_head: u64, target_base: u64) -> Result<u64> {
        let mut current_soinfo = solist_head;
        let mut iteration_count = 0;
        const MAX_ITERATIONS: usize = 1000;

        while current_soinfo != 0 && iteration_count < MAX_ITERATIONS {
            let soinfo = self.parse_soinfo(current_soinfo)?;

            println!(
                "[*] soinfo base: {:#x}, size: {:#x}, next: {:#x}",
                soinfo.base, soinfo.size, soinfo.next
            );

            if soinfo.base == target_base {
                return Ok(soinfo.size);
            }

            current_soinfo = soinfo.next;
            iteration_count += 1;
        }

        Err(anyhow!("Could not find target SO in soinfo chain"))
    }

    fn search_soinfo_chain(&self, solist_head: u64, target_base: u64) -> Result<u64> {
        let chain_data = self.read_process_memory(solist_head, 256 * 1024)?;

        let target_pattern = target_base.to_le_bytes();

        for window in chain_data.windows(target_pattern.len()) {
            if window == target_pattern {
                let offset = window.as_ptr() as usize - chain_data.as_ptr() as usize + 8;
                if offset + 8 <= chain_data.len() {
                    let mut cursor = std::io::Cursor::new(&chain_data[offset..offset + 8]);
                    if let Ok(size) = cursor.read_u64::<LittleEndian>() {
                        println!("[+] Found soinfo size: {}", size);
                        return Ok(size);
                    }
                }
            }
        }

        Err(anyhow!("Could not find target base in soinfo chain data"))
    }

    fn dump_so(&self, target_base: u64, so_size: u64) -> Result<PathBuf> {
        println!("[+] Dumping SO from {:#x}, size: {}", target_base, so_size);

        let data = self.read_process_memory(target_base, so_size as usize)?;

        let base_name = Path::new(&self.target_name)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();

        let output_filename = format!("{}_{:#x}_{}_dump.so", base_name, target_base, so_size);
        let output_path = self.output_dir.join(&output_filename);

        let mut output_file = File::create(&output_path)?;
        output_file.write_all(&data)?;

        println!("[+] SO dumped to: {}", output_path.display());

        if self.auto_fix {
            if let Err(e) = self.auto_fix_so(target_base, &output_path) {
                eprintln!("[!] Auto-fix failed: {}, but SO dump succeeded", e);
            }
        }

        Ok(output_path)
    }

    fn auto_fix_so(&self, target_base: u64, so_path: &Path) -> Result<()> {
        let so_name = so_path
            .file_name()
            .ok_or_else(|| anyhow!("Invalid SO path"))?
            .to_string_lossy();

        let fixed_path = format!("{}.fix.so", so_name);
        let fixed_output_path = self.output_dir.join(&fixed_path);

        println!("[+] Auto-fixing SO file: {}", so_name);

        self.sofixer.extract()?;

        self.sofixer.fix_so(
            target_base,
            &so_path.to_string_lossy(),
            &fixed_output_path.to_string_lossy(),
        )?;

        Ok(())
    }

    pub fn dump(&self) -> Result<()> {
        println!(
            "[+] Starting SO dump process for target: {}",
            self.target_name
        );
        println!("[+] Target PID: {}", self.target_pid);
        println!("[+] Architecture: 64-bit only (ARM64/x86_64)");

        if self.auto_fix {
            println!("[+] Extracting SoFixer binary...");
            self.extract_sofixer()?;
        }

        let solist_offset = self.get_solist_offset()?;
        println!("[+] solist offset: {:#x}", solist_offset);

        self.stop_process()?;

        let result = (|| -> Result<()> {
            let linker_base = self.get_linker_base()?;
            println!("[+] linker64 base: {:#x}", linker_base);

            let (target_base, target_end) = self.get_target_mapping()?;
            let target_size = target_end - target_base;
            println!(
                "[+] target base: {:#x}, end: {:#x}, size: {}",
                target_base, target_end, target_size
            );

            let solist_addr = linker_base + solist_offset;
            println!("[+] solist addr: {:#x}", solist_addr);

            let solist_head = self.get_solist_head(solist_addr)?;

            let so_size = match self.find_target_soinfo(solist_head, target_base) {
                Ok(size) => {
                    if size > target_size * 10 {
                        println!("[*] soinfo size too large, using target_size");
                        target_size
                    } else {
                        size
                    }
                }
                Err(_) => {
                    println!("[*] Could not find in soinfo chain, trying backup search method");
                    match self.search_soinfo_chain(solist_head, target_base) {
                        Ok(size) => {
                            if size > target_size * 10 {
                                println!("[*] backup search size too large, using target_size");
                                target_size
                            } else {
                                size
                            }
                        }
                        Err(_) => {
                            println!("[*] Backup search failed, using target_size");
                            target_size
                        }
                    }
                }
            };

            let _dump_path = self.dump_so(target_base, so_size)?;

            Ok(())
        })();

        self.continue_process()?;

        result
    }
}
