#[derive(Debug)]
pub struct MemoryMapping {
    pub start: u64,
    pub end: u64,
    #[allow(dead_code)]
    pub permissions: String,
    #[allow(dead_code)]
    pub offset: u64,
    #[allow(dead_code)]
    pub device: String,
    #[allow(dead_code)]
    pub inode: u64,
    pub pathname: String,
}

#[derive(Debug)]
pub struct SoInfo {
    pub base: u64,
    pub size: u64,
    pub next: u64,
}
