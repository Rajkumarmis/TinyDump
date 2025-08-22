use anyhow::{anyhow, Result};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

// SoFixer64 binary data will be embedded here
// Author: mrack <https://github.com/mrack>
const SOFIXER64_BINARY: &[u8] = include_bytes!("../../bin/sofixer64");

pub struct SoFixer {
    binary_path: String,
}

impl SoFixer {
    pub fn new() -> Result<Self> {
        let binary_path = "./SoFixer".to_string();
        Ok(Self { binary_path })
    }

    pub fn extract(&self) -> Result<()> {
        let output_path = Path::new(&self.binary_path);

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = fs::File::create(output_path)?;
        file.write_all(SOFIXER64_BINARY)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(output_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(output_path, perms)?;
        }

        println!("[+] SoFixer extracted to: {}", self.binary_path);
        Ok(())
    }

    pub fn fix_so(&self, base: u64, so_path: &str, output_path: &str) -> Result<()> {
        if !Path::new(&self.binary_path).exists() {
            self.extract()?;
        }

        let output = Command::new(&self.binary_path)
            .arg("-m")
            .arg(format!("{:#x}", base))
            .arg("-s")
            .arg(so_path)
            .arg("-o")
            .arg(output_path)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("SoFixer failed: {}", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.is_empty() {
            println!("[+] SoFixer output: {}", stdout);
        }

        println!("[+] SO fixed successfully: {}", output_path);
        Ok(())
    }

    pub fn cleanup(&self) -> Result<()> {
        if Path::new(&self.binary_path).exists() {
            fs::remove_file(&self.binary_path)?;
            println!("[+] SoFixer binary cleaned up");
        }
        Ok(())
    }
}

impl Drop for SoFixer {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
