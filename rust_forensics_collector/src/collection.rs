use std::process::Command;
use std::path::{Path, PathBuf};
use anyhow::{Result, Context};
use log::{info, warn};
use std::time::Instant;

pub fn collect_memory(winpmem_path: &Path, local_dir: &Path) -> Result<PathBuf> {
    let hostname = whoami::hostname();
    let output_path = local_dir.join(format!("memory_{}.raw", hostname));
    info!("Starting memory dump to {:?}...", output_path);
    
    let start = Instant::now();
    // go-winpmem.exe acquire <output_file>
    let status = Command::new(winpmem_path)
        .args(["acquire", output_path.to_str().unwrap()])
        .status()
        .context("Failed to execute winpmem")?;
        
    let duration = start.elapsed();
    
    if status.success() && output_path.exists() {
        let size_gb = std::fs::metadata(&output_path)?.len() as f64 / 1_073_741_824.0;
        info!("Memory dump complete: {:.2}GB in {:.1} minutes", size_gb, duration.as_secs_f64() / 60.0);
        Ok(output_path)
    } else {
        anyhow::bail!("Memory dump failed with status: {}", status);
    }
}

pub fn collect_kape(kape_path: &Path, local_output: &Path, targets: &str) -> Result<()> {
    info!("Running KAPE with targets: {}", targets);
    
    let kape_dir = kape_path.parent().unwrap();
    let start = Instant::now();
    
    // kape.exe --tsource C:\ --tdest ... --target ... --zv false
    let status = Command::new(kape_path)
        .current_dir(kape_dir) 
        .args([
            "--tsource", "C:\\",
            "--tdest", local_output.to_str().unwrap(),
            "--target", targets,
            "--zv", "false"
        ])
        .status()
        .context("Failed to execute KAPE")?;

    let duration = start.elapsed();
    if status.success() {
        info!("KAPE completed in {:.1} minutes", duration.as_secs_f64() / 60.0);
        Ok(())
    } else {
         warn!("KAPE exited with code {}", status);
         Ok(()) 
    }
}
