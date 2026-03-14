mod registry;
mod routes;
mod state;

use clap::Parser;
use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// KaliHeker Registry Viewer — Interactive web-based Windows registry hive browser
#[derive(Parser)]
#[command(name = "registry_viewer")]
#[command(version = "1.0.0")]
#[command(about = "Interactive web-based Windows registry hive viewer")]
struct Cli {
    /// Path to a registry hive file or directory to pre-load
    #[arg(short, long)]
    path: Option<PathBuf>,

    /// Server port
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// Auto-open browser after starting
    #[arg(long, default_value_t = false)]
    open: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "registry_viewer=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let mut app_state = state::AppState::new();

    // Pre-load hives from CLI path if provided.
    if let Some(ref hive_path) = cli.path {
        let loaded = if hive_path.is_dir() {
            tracing::info!("Loading hives from directory: {}", hive_path.display());
            preload_from_directory(&mut app_state, hive_path)
        } else {
            tracing::info!("Loading hive from: {}", hive_path.display());
            match registry::load_hive_from_path(hive_path) {
                Ok(entry) => {
                    tracing::info!(
                        "Loaded '{}' ({} bytes, id={})",
                        entry.name,
                        entry.size,
                        entry.id
                    );
                    app_state.hives.insert(entry.id.clone(), entry);
                    1
                }
                Err(e) => {
                    tracing::error!("Failed to load hive: {}", e);
                    std::process::exit(1);
                }
            }
        };

        if loaded == 0 {
            tracing::error!(
                "No valid registry hives found at {}",
                hive_path.display()
            );
            std::process::exit(1);
        }
    } else {
        let loaded = preload_from_config_dir(&mut app_state, Path::new("config"));
        if loaded == 0 {
            tracing::info!("No default hives found in ./config; use --path or upload via UI");
        }
    }

    let shared_state = Arc::new(RwLock::new(app_state));
    let app = routes::build_router(shared_state);

    let addr = format!("0.0.0.0:{}", cli.port);
    tracing::info!("Registry Viewer starting at http://127.0.0.1:{}", cli.port);

    if cli.open {
        let url = format!("http://127.0.0.1:{}", cli.port);
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let _ = open::that(&url);
        });
    }

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn preload_from_config_dir(app_state: &mut state::AppState, config_dir: &Path) -> usize {
    const DEFAULT_HIVES: [&str; 5] = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];

    let mut loaded = 0usize;
    for name in DEFAULT_HIVES {
        let hive_path = config_dir.join(name);
        if !hive_path.exists() {
            continue;
        }

        match registry::load_hive_from_path(&hive_path) {
            Ok(entry) => {
                tracing::info!(
                    "Preloaded '{}' from {} ({} bytes)",
                    entry.name,
                    hive_path.display(),
                    entry.size
                );
                app_state.hives.insert(entry.id.clone(), entry);
                loaded += 1;
            }
            Err(e) => {
                tracing::warn!("Skipping {}: {}", hive_path.display(), e);
            }
        }
    }

    loaded
}

fn preload_from_directory(app_state: &mut state::AppState, dir: &Path) -> usize {
    let mut loaded = 0usize;
    let mut hive_paths = collect_hive_files_recursive(dir);

    hive_paths.sort();

    for hive_path in hive_paths {
        match registry::load_hive_from_path(&hive_path) {
            Ok(entry) => {
                tracing::info!(
                    "Loaded '{}' from {} ({} bytes)",
                    entry.name,
                    hive_path.display(),
                    entry.size
                );
                app_state.hives.insert(entry.id.clone(), entry);
                loaded += 1;
            }
            Err(e) => {
                tracing::warn!("Skipping {}: {}", hive_path.display(), e);
            }
        }
    }

    loaded
}

fn collect_hive_files_recursive(root: &Path) -> Vec<PathBuf> {
    let mut queue = VecDeque::new();
    let mut files = Vec::new();
    queue.push_back(root.to_path_buf());

    while let Some(dir) = queue.pop_front() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Skipping unreadable directory {}: {}", dir.display(), e);
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                queue.push_back(path);
                continue;
            }

            if !path.is_file() {
                continue;
            }

            if is_primary_registry_hive_file(&path) {
                files.push(path);
            }
        }
    }

    files.sort();
    files
}

fn is_primary_registry_hive_file(path: &Path) -> bool {
    let name_upper = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_uppercase();

    matches!(
        name_upper.as_str(),
        "SYSTEM"
            | "SOFTWARE"
            | "SAM"
            | "SECURITY"
            | "DEFAULT"
            | "NTUSER.DAT"
            | "USRCLASS.DAT"
    )
}
