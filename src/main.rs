mod dumper;
mod utils;

use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::PathBuf;

use dumper::{DexDumper, SoDumper};
use utils::{get_pid_by_name, list_so_files};

#[derive(Parser, Debug)]
#[command(name = "tinydump")]
#[command(about = "Android native SO and DEX dumper")]
#[command(version)]
#[command(author = "mrack <https://github.com/mrack>")]
struct Args {
    #[arg(short, long)]
    target: Option<String>,

    #[arg(short = 'p', long)]
    attach_pid: Option<u32>,

    #[arg(short = 'n', long)]
    attach_name: Option<String>,

    #[arg(short, long, default_value = ".")]
    output: PathBuf,

    #[arg(long)]
    dex: bool,

    #[arg(long)]
    list_so: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let target_pid = if let Some(pid) = args.attach_pid {
        pid
    } else {
        let process_name = args
            .attach_name
            .ok_or_else(|| anyhow!("Need --attach-pid or --attach-name"))?;
        get_pid_by_name(&process_name)?
    };

    std::fs::create_dir_all(&args.output)?;

    if args.list_so {
        // 列举SO文件模式
        println!("[+] SO list mode");
        println!("[+] PID: {}", target_pid);
        
        let so_files = list_so_files(target_pid)
            .map_err(|e| anyhow!("Failed to list SO files: {}", e))?;
        
        if so_files.is_empty() {
            println!("[!] No SO files found for PID {}", target_pid);
        } else {
            println!("[+] Found {} SO files:", so_files.len());
            println!("{:<50} {:<18} {:<18} {:<10} {:<20}", "Name", "Start", "End", "Size", "Permissions");
            println!("{:-<120}", "");
            
            for so in so_files {
                let size_str = format!("{}KB", so.size / 1024);
                
                println!("{:<50} {:<18x} {:<18x} {:<10} {:<20}", 
                    so.name, so.start, so.end, size_str, so.permissions);
            }
        }
    } else if args.dex {
        // DEX模式
        println!("[+] DEX dump mode");
        println!("[+] PID: {}", target_pid);
        println!("[+] Output: {}", args.output.display());

        let mut dex_dumper =
            DexDumper::new(target_pid as i32).map_err(|e| anyhow!("DexDumper failed: {}", e))?;

        dex_dumper
            .attach_process()
            .map_err(|e| anyhow!("Attach failed: {}", e))?;

        dex_dumper
            .search_dex(&args.output.to_string_lossy())
            .map_err(|e| anyhow!("DEX search failed: {}", e))?;

        println!("[+] DEX dump done");
    } else {
        // SO dump模式
        let target_name = args
            .target
            .ok_or_else(|| anyhow!("Need --target for SO dump"))?;

        let dumper = SoDumper::new(target_pid, target_name, args.output)
            .map_err(|e| anyhow!("SoDumper failed: {}", e))?;
        dumper.dump()?;

        println!("[+] SO dump done");
    }

    Ok(())
}
