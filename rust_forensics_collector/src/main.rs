use clap::Parser;
use log::{info, warn, error};
use chrono::Local;
use std::path::PathBuf;
use anyhow::Context;

mod smb;
mod tools;
mod collection;
mod utils;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// KAPE targets to collect
    #[arg(long, default_value = "!SANS_Triage")]
    pub targets: String,

    /// SMB Server IP/Hostname
    #[arg(long, default_value = "172.30.94.82")]
    pub smb_server: String,

    /// SMB Share Name
    #[arg(long, default_value = "forensics")]
    pub smb_share: String,

    /// SMB Username
    #[arg(long, default_value = "forensics")]
    pub smb_user: String,

    /// SMB Password
    #[arg(long, default_value = "kali1234")]
    pub smb_password: String,

    /// Case Identifier (auto-generated if not provided)
    #[arg(long)]
    pub case_id: Option<String>,
}

fn main() -> anyhow::Result<()> {
    utils::setup_logger();
    let args = Args::parse();

    let hostname = whoami::hostname();
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let case_id = args.case_id.clone().unwrap_or_else(|| format!("CASE_{}_{}", timestamp, hostname));

    utils::log_header("Forensic Collection Started");
    info!("Case ID: {}", case_id);
    info!("Target System: {}", hostname);

    let is_admin = utils::is_admin();
    if !is_admin {
        warn!("WARNING: Not running as admin - memory dump will fail!");
    }

    // Prepare Local Directory
    let temp_dir = std::env::temp_dir();
    let local_dir = temp_dir.join(format!("Forensics_{}", case_id));
    std::fs::create_dir_all(&local_dir)?;
    info!("Created local directory: {:?}", local_dir);

    // SMB Connection
    // Using Z: as default drive letter
    let drive_letter = "Z:";
    smb::connect(&args.smb_server, &args.smb_share, &args.smb_user, &args.smb_password, drive_letter)?;

    // Prepare Remote Case Directory
    let remote_base = PathBuf::from(format!(r"{}\", drive_letter));
    let remote_case_dir = remote_base.join("output").join(&case_id);
    if !remote_case_dir.exists() {
        std::fs::create_dir_all(&remote_case_dir).context("Failed to create remote case directory")?;
    }
    info!("Created remote case folder: {:?}", remote_case_dir);

    // Copy Tools
    let (winpmem_path, kape_path) = tools::copy_tools(drive_letter, &local_dir)?;

    // Memory Collection
    let mut memory_collected = false;
    if is_admin {
        utils::log_header("STEP 3: Memory Acquisition (Priority)");
        match collection::collect_memory(&winpmem_path, &local_dir) {
            Ok(local_dump) => {
                info!("Transferring memory dump to server...");
                let filename = local_dump.file_name().unwrap();
                let remote_dump = remote_case_dir.join(filename);
                std::fs::copy(&local_dump, &remote_dump)?;
                info!("Memory dump transferred to server");
                
                // Cleanup local dump
                let _ = std::fs::remove_file(local_dump);
                memory_collected = true;
            },
            Err(e) => error!("Memory dump failed: {}", e),
        }
    } else {
        warn!("SKIPPED: Memory dump requires admin privileges");
    }

    // KAPE Collection
    utils::log_header("STEP 4: KAPE Artifact Collection");
    let local_artifacts = local_dir.join("artifacts");
    std::fs::create_dir_all(&local_artifacts)?;
    
    collection::collect_kape(&kape_path, &local_artifacts, &args.targets)?;

    info!("Transferring artifacts to server...");
    let remote_artifacts = remote_case_dir.join("artifacts");
    if !remote_artifacts.exists() {
        std::fs::create_dir_all(&remote_artifacts)?;
    }
    
    // Recursive copy back to SMB
    // We can reuse our copy_dir_all helper if we expose it, or use a crate. 
    // Since tools::copy_dir_all is private, let's implement validation manually or move it to utils.
    // For simplicity, let's just make tools::copy_dir_all public or duplicate.
    // I'll assume we need to implement it here or reuse.
    // Actually, I can just use `xcopy` or `robocopy` or `Copy-Item` via powershell if lazy, 
    // but better to stick to Rust. I'll implement a recursive copy helper in utils.
    match utils::copy_dir_recursive(&local_artifacts, &remote_artifacts) {
        Ok(_) => info!("Artifacts transferred to server"),
        Err(e) => error!("Failed to transfer artifacts: {}", e),
    }

    // Manifest and Hashes
    utils::log_header("STEP 5: Create manifest and hash log");
    let manifest_path = remote_case_dir.join("manifest.txt");
    let content = format!(
        "Case ID: {}\nSource System: {}\nCollection Time: {} UTC\nKAPE Targets: {}\nMemory Collected: {}\nCollected By: {}\n",
        case_id, hostname, chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"), args.targets, memory_collected, whoami::username()
    );
    std::fs::write(manifest_path, content)?;

    info!("Generating hashes (SHA256 & MD5)...");
    let hash_log = remote_case_dir.join("hashes.txt");
    let mut hash_entries = String::from("# SHA-256 and MD5 Hashes\n\n");
    
    for entry in walkdir::WalkDir::new(&remote_case_dir) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();
            if path.file_name().unwrap() == "hashes.txt" { continue; }
            
            match utils::calculate_hashes(path.to_str().unwrap()) {
                Ok((sha256, md5)) => {
                    let rel_path = path.strip_prefix(&remote_case_dir).unwrap_or(path);
                    hash_entries.push_str(&format!("{} {} {}\n", sha256, md5, rel_path.display()));
                },
                Err(e) => warn!("Failed to hash {:?}: {}", path, e),
            }
        }
    }
    std::fs::write(hash_log, hash_entries)?;
    info!("Manifest and hashes created");

    // Cleanup
    utils::log_header("STEP 6: Cleanup");
    info!("Cleaning up local files...");
    let _ = std::fs::remove_dir_all(&local_dir);
    smb::disconnect(drive_letter);

    utils::log_header("Collection Complete");
    info!("Case ID: {}", case_id);
    info!("Data saved to: \\\\{}\\{}\\output\\{}", args.smb_server, args.smb_share, case_id);

    Ok(())
}
