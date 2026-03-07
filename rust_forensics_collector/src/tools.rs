use std::path::{Path, PathBuf};
use std::fs;
use anyhow::{Context, Result};
use log::info;

pub fn copy_tools(drive: &str, local_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    // drive is like "Z:", so path is "Z:\tools"
    let drive_path = Path::new(drive);
    let remote_tools = drive_path.join("tools");
    
    // Hardcoded winpmem name as per script
    let winpmem_exe_name = "go-winpmem_amd64_1.0-rc2_signed.exe";
    let remote_winpmem = remote_tools.join(winpmem_exe_name);
    let local_winpmem = local_dir.join(winpmem_exe_name);

    if !remote_winpmem.exists() {
        anyhow::bail!("winpmem not found at {:?}", remote_winpmem);
    }

    info!("Copying winpmem...");
    fs::copy(&remote_winpmem, &local_winpmem)
        .with_context(|| format!("Failed to copy winpmem from {:?}", remote_winpmem))?;

    let remote_kape = remote_tools.join("KAPE");
    let local_kape_dir = local_dir.join("KAPE");
    
    if !remote_kape.exists() {
        anyhow::bail!("KAPE folder not found at {:?}", remote_kape);
    }

    info!("Copying KAPE folder (this may take a moment)...");
    copy_dir_all(&remote_kape, &local_kape_dir)
        .context("Failed to copy KAPE folder")?;

    let kape_exe = local_kape_dir.join("kape.exe");
    if !kape_exe.exists() {
        anyhow::bail!("kape.exe not found in copied folder!");
    }

    Ok((local_winpmem, kape_exe))
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}
