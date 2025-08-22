use anyhow::{anyhow, Result};
use std::collections::HashMap;

pub fn get_pid_by_name(process_name: &str) -> Result<u32> {
    let proc_dir = std::fs::read_dir("/proc")?;

    for entry in proc_dir {
        let entry = entry?;
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();

        if let Ok(pid) = pid_str.parse::<u32>() {
            let cmdline_path = format!("/proc/{}/cmdline", pid);
            if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                if cmdline.contains(process_name) {
                    return Ok(pid);
                }
            }
        }
    }

    Err(anyhow!("Process {} not found", process_name))
}

/// 列举指定PID的所有SO文件
pub fn list_so_files(pid: u32) -> Result<Vec<SoFileInfo>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = std::fs::read_to_string(&maps_path)
        .map_err(|_| anyhow!("Failed to read /proc/{}/maps", pid))?;

    let mut so_files: HashMap<String, SoFileInfo> = HashMap::new();

    for line in content.lines() {
        if line.contains(".so") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let addr_range: Vec<&str> = parts[0].split('-').collect();
                if addr_range.len() == 2 {
                    if let (Ok(start), Ok(end)) = (
                        u64::from_str_radix(addr_range[0], 16),
                        u64::from_str_radix(addr_range[1], 16),
                    ) {
                        let permissions = parts[1].to_string();
                        let pathname = parts[5..].join(" ");

                        if !pathname.is_empty() && pathname.contains(".so") {
                            let so_name = pathname.split('/').last().unwrap_or(&pathname).to_string();
                            
                            if let Some(existing) = so_files.get_mut(&so_name) {
                                // 如果已存在同名SO，更新地址范围
                                existing.start = existing.start.min(start);
                                existing.end = existing.end.max(end);
                                existing.size = existing.end - existing.start;
                            } else {
                                so_files.insert(so_name.clone(), SoFileInfo {
                                    name: so_name,
                                    path: pathname,
                                    start,
                                    end,
                                    size: end - start,
                                    permissions,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let mut result: Vec<SoFileInfo> = so_files.into_values().collect();
    result.sort_by(|a, b| a.start.cmp(&b.start));
    Ok(result)
}

/// SO文件信息结构体
#[derive(Debug, Clone)]
pub struct SoFileInfo {
    pub name: String,
    pub path: String,
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub permissions: String,
}
