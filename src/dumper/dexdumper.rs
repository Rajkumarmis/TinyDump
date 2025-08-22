use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use proc_maps::MapRange;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use regex::bytes::Regex;
use std::cell::RefCell;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

// Constants for DEX file structure
// Author: mrack <https://github.com/mrack>
const DEX_MAGIC: &[u8] = b"dex\n035\0";
const DEX_HEADER_SIZE: u32 = 0x70;
const DEX_HEADER_SIZE_OFFSET: u64 = 0x24;
const DEX_FILE_SIZE_OFFSET: u64 = 0x20;
const DEX_ENDIAN_TAG_OFFSET: u64 = 0x28;
const DEX_STRING_IDS_OFFSET: u64 = 0x3c;
const DEX_MAP_OFFSET: u64 = 0x34;
const DEX_ENDIAN_TAG: u32 = 0x12345678;
const DEX_ENDIAN_TAG_SWAPPED: u32 = 0x78563412;
const MIN_MEMORY_SIZE: usize = 0x60;

#[derive(Debug)]
pub enum DexDumperError {
    ProcessNotFound(i32),
    FailedToAttach,
    FailedToDetach,
    FileCreationFailed,
    IoError(std::io::Error),
}

impl std::fmt::Display for DexDumperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DexDumperError::ProcessNotFound(pid) => write!(f, "Process {} not found", pid),
            DexDumperError::FailedToAttach => write!(f, "Failed to attach to process"),
            DexDumperError::FailedToDetach => write!(f, "Failed to detach from process"),
            DexDumperError::FileCreationFailed => write!(f, "Failed to create output file"),
            DexDumperError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for DexDumperError {}

impl From<std::io::Error> for DexDumperError {
    fn from(err: std::io::Error) -> Self {
        DexDumperError::IoError(err)
    }
}

pub struct DexDumper {
    pid: Pid,
    mem_fd: RefCell<std::fs::File>,
    maps: Vec<MapRange>,
    dex_regex: Regex,
}

impl DexDumper {
    pub fn new(pid: i32) -> Result<Self, DexDumperError> {
        let mem_fd = std::fs::File::open(format!("/proc/{}/mem", pid))
            .map_err(|_| DexDumperError::ProcessNotFound(pid))?;

        let dex_regex =
            Regex::new(r"\x64\x65\x78\x0a\x30..\x00").expect("Failed to compile DEX regex");

        Ok(DexDumper {
            pid: Pid::from_raw(pid),
            maps: Vec::new(),
            mem_fd: RefCell::new(mem_fd),
            dex_regex,
        })
    }

    pub fn attach_process(&mut self) -> Result<(), DexDumperError> {
        kill(self.pid, Signal::SIGSTOP).map_err(|_| DexDumperError::FailedToAttach)?;

        self.maps = proc_maps::get_process_maps(self.pid.as_raw())
            .map_err(|_| DexDumperError::FailedToAttach)?;

        Ok(())
    }

    pub fn detach_process(&self) -> Result<(), DexDumperError> {
        kill(self.pid, Signal::SIGCONT).map_err(|_| DexDumperError::FailedToDetach)
    }

    fn read_dex_header_value(&self, address: usize, offset: u64) -> Option<u32> {
        let mut cursor = self.mem_fd.borrow_mut();
        cursor.seek(SeekFrom::Start(address as u64 + offset)).ok()?;
        cursor.read_u32::<LittleEndian>().ok()
    }

    fn guess_dex_size(&self, dex_header_addr: usize) -> Option<(usize, usize)> {
        let file_size = self.read_dex_header_value(dex_header_addr, DEX_FILE_SIZE_OFFSET)?;

        let string_ids_off = self.read_dex_header_value(dex_header_addr, DEX_STRING_IDS_OFFSET)?;
        if string_ids_off != DEX_HEADER_SIZE {
            return None;
        }

        let map_off = self.read_dex_header_value(dex_header_addr, DEX_MAP_OFFSET)?;
        let map_size = self.read_dex_header_value(dex_header_addr + map_off as usize, 0)?;

        let real_size = map_off
            .checked_add(map_size.checked_mul(0xC)?)?
            .checked_add(4)?;

        Some((file_size as usize, real_size as usize))
    }

    fn fix_dex_header(dex: &[u8]) -> Option<Vec<u8>> {
        let mut fixed_dex = dex.to_vec();
        let mut cursor = Cursor::new(&mut fixed_dex);

        cursor.write_all(DEX_MAGIC).ok()?;

        cursor.seek(SeekFrom::Start(DEX_FILE_SIZE_OFFSET)).ok()?;
        cursor.write_u32::<LittleEndian>(dex.len() as u32).ok()?;

        cursor.seek(SeekFrom::Start(DEX_HEADER_SIZE_OFFSET)).ok()?;
        cursor.write_u32::<LittleEndian>(DEX_HEADER_SIZE).ok()?;

        cursor.seek(SeekFrom::Start(DEX_ENDIAN_TAG_OFFSET)).ok()?;
        let endian_tag = cursor.read_u32::<LittleEndian>().ok()?;
        if endian_tag != DEX_ENDIAN_TAG && endian_tag != DEX_ENDIAN_TAG_SWAPPED {
            cursor.seek(SeekFrom::Start(DEX_ENDIAN_TAG_OFFSET)).ok()?;
            cursor.write_u32::<LittleEndian>(DEX_ENDIAN_TAG).ok()?;
        }

        Some(fixed_dex)
    }

    fn should_skip_memory_region(filename: Option<&std::path::Path>) -> bool {
        if let Some(f) = filename {
            f.starts_with("/data/dalvik-cache/") || f.starts_with("/system/")
        } else {
            false
        }
    }

    fn process_dex_found(&self, out_path: &Path, real_addr: usize) -> Result<(), DexDumperError> {
        if let Some((file_size, actual_size)) = self.guess_dex_size(real_addr) {
            if let Some(data) = self.read_memory_proc(real_addr, actual_size) {
                println!(
                    "Found DEX at {:#08x}, file_size: {:#08x}, actual_size: {:#08x}",
                    real_addr, file_size, actual_size
                );

                let output_path = out_path.join(format!("dex_{:#08x}.dex", real_addr));
                let mut file = std::fs::File::create(&output_path)
                    .map_err(|_| DexDumperError::FileCreationFailed)?;

                file.write_all(&data)?;
                println!("Saved DEX to: {}", output_path.display());
            } else {
                println!(
                    "Failed to read memory at {:#08x} - {:#08x}",
                    real_addr,
                    real_addr + actual_size
                );
            }
        }
        Ok(())
    }

    fn process_memory_region(
        &self,
        out_path: &Path,
        memory_map: &MapRange,
    ) -> Result<(), DexDumperError> {
        if let Some(mem) = self.read_memory_proc(memory_map.start(), memory_map.size()) {
            for dex_match in self.dex_regex.find_iter(&mem) {
                let real_addr = memory_map.start() + dex_match.start();
                self.process_dex_found(out_path, real_addr)?;
            }

            if mem.len() >= 3 && &mem[0..3] != b"dex" {
                if let Some((file_size, guess_size)) = self.guess_dex_size(memory_map.start()) {
                    println!(
                        "No header found, file_size: {:#08x}, guess_size: {:#08x}",
                        file_size, guess_size
                    );

                    if let Some(data) = self.read_memory_proc(memory_map.start(), guess_size) {
                        if let Some(fixed_dex) = Self::fix_dex_header(&data) {
                            let output_path =
                                out_path.join(format!("dex_{:#08x}.dex", memory_map.start()));
                            let mut file = std::fs::File::create(&output_path)
                                .map_err(|_| DexDumperError::FileCreationFailed)?;

                            file.write_all(&fixed_dex)?;
                            println!("Saved fixed DEX to: {}", output_path.display());
                        }
                    } else {
                        println!(
                            "Failed to read memory at {:#08x} - {:#08x}",
                            memory_map.start(),
                            memory_map.start() + guess_size
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub fn search_dex(&mut self, out_path: &str) -> Result<(), DexDumperError> {
        let out_path = Path::new(out_path);

        std::fs::create_dir_all(out_path)?;

        let filtered_maps: Vec<_> = self
            .maps
            .iter()
            .filter(|m| m.is_read() && m.size() > MIN_MEMORY_SIZE)
            .filter(|m| !Self::should_skip_memory_region(m.filename()))
            .collect();

        println!(
            "Searching {} memory regions for DEX files...",
            filtered_maps.len()
        );

        for memory_map in filtered_maps {
            if let Err(e) = self.process_memory_region(out_path, memory_map) {
                eprintln!(
                    "Error processing memory region {:#08x}: {}",
                    memory_map.start(),
                    e
                );
            }
        }

        println!("DEX search completed");
        Ok(())
    }

    fn read_memory_proc(&self, address: usize, size: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let mut mem_fd = self.mem_fd.borrow_mut();

        if mem_fd.seek(SeekFrom::Start(address as u64)).is_err() {
            return None;
        }

        if mem_fd.read_exact(&mut buffer).is_err() {
            return None;
        }

        Some(buffer)
    }
}

impl Drop for DexDumper {
    fn drop(&mut self) {
        let _ = self.detach_process();
    }
}
