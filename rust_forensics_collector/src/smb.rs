use std::process::Command;
use anyhow::{Context, Result};
use log::info;

pub fn connect(server: &str, share: &str, user: &str, pass: &str, drive: &str) -> Result<()> {
    // Disconnect if exists (silently)
    let _ = Command::new("net")
        .args(["use", drive, "/delete", "/y"])
        .output();

    let remote_path = format!(r"\\{}\{}", server, share);
    info!("Connecting to SMB share {}...", remote_path);

    // net use Z: \\server\share password /user:username
    let status = Command::new("net")
        .args(["use", drive, &remote_path, pass, &format!("/user:{}", user)])
        .status()
        .context("Failed to execute net use command")?;

    if status.success() {
        info!("Connected to SMB share on {}", drive);
        Ok(())
    } else {
        // Capture stderr if possible, but status check is enough for now
        anyhow::bail!("Failed to connect to SMB share. Check credentials and network.");
    }
}

pub fn disconnect(drive: &str) {
    let _ = Command::new("net")
        .args(["use", drive, "/delete", "/y"])
        .output();
}
