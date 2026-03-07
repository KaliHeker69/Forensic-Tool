use sha2::{Sha256, Digest};
use md5::Md5;
use std::fs::File;
use std::io::{Read, BufReader};
use log::{info, warn, error};

pub fn setup_logger() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_target(false)
        .format_timestamp_secs()
        .init();
}

pub fn is_admin() -> bool {
    is_elevated::is_elevated()
}

pub fn calculate_hashes(path: &str) -> anyhow::Result<(String, String)> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut sha256 = Sha256::new();
    let mut md5 = Md5::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 { break; }
        sha256.update(&buffer[..count]);
        md5.update(&buffer[..count]);
    }

    Ok((
        hex::encode(sha256.finalize()),
        hex::encode(md5.finalize())
    ))
}

pub fn log_header(message: &str) {
    info!("========================================");
    info!("{}", message);
    info!("========================================");
}

pub fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> anyhow::Result<()> {
    if !dst.exists() {
        std::fs::create_dir_all(dst)?;
    }
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else {
            std::fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}
