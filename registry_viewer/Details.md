Registry Viewer — Implementation Plan
Context
Build a Rust-based web UI for parsing and viewing offline Windows registry hive files (NTUSER.DAT, SAM, SYSTEM, SOFTWARE, SECURITY, etc.), with a look and feel similar to Windows regedit.exe. Part of the KaliHeker forensic toolkit at /Users/kali/Codes/wsl/.

Technology Stack
Component	Choice	Rationale
Registry parsing	notatin 1.0 (Apache-2.0)	Stable, iterator API, transaction log support, by Stroz Friedberg
Web framework	axum 0.8 + tokio	Best Rust ecosystem integration, used in sibling portal project
Templating	askama (compile-time)	Type-safe, fast, single-binary friendly
Frontend	htmx 2.0 + dark CSS	Lazy tree loading, no JS build step, single binary
Static embedding	include_dir	Already used in sibling portal project
CLI	clap 4 (derive)	Consistent with all sibling projects
Architecture
Key design: Store raw hive bytes (Vec<u8>) in Arc<RwLock<AppState>>. Recreate a notatin::Parser from Cursor<Vec<u8>> per request (~1ms overhead). This avoids thread-safety issues since Parser is not Send+Sync.

Layout: Toolbar (file upload + search) | Sidebar (loaded hives) | Split-pane (tree panel + detail panel)

Data flow: Click tree node arrow → htmx GET /api/keys/{hive_id}?path=... → server creates parser, navigates to key, returns HTML fragment of children → htmx swaps into DOM. Click node name → htmx GET /api/values/{hive_id}?path=... → returns value table fragment.

File Structure
registry_viewer/
├── Cargo.toml
├── askama.toml                   # Template directory config
├── src/
│   ├── main.rs                   # CLI args, server setup
│   ├── state.rs                  # AppState, HiveEntry
│   ├── registry.rs               # notatin wrapper (parser creation, tree nav, values, search)
│   └── routes/
│       ├── mod.rs                # Router assembly + static file serving
│       ├── pages.rs              # GET / (main page)
│       ├── hives.rs              # POST /api/upload, GET /api/hives, DELETE /api/hives/{id}
│       ├── keys.rs               # GET /api/keys/{hive_id}?path= (tree children fragment)
│       ├── values.rs             # GET /api/values/{hive_id}?path= (detail panel fragment)
│       └── search.rs             # GET /api/search/{hive_id}?q=
├── templates/
│   ├── index.html                # Full page shell
│   ├── hive_list.html            # Sidebar: loaded hives
│   ├── tree_children.html        # htmx fragment: child key nodes
│   ├── detail_panel.html         # htmx fragment: value table
│   └── search_results.html       # htmx fragment: search results
└── static/
    ├── style.css                 # Dark theme, split-pane, regedit styling
    ├── htmx.min.js               # Vendored htmx 2.0 (~14KB gzipped)
    └── app.js                    # Split-pane resize, drag-drop upload, keyboard nav
Implementation Phases
Phase 1: Project Skeleton (compiles and serves a page)
Create Cargo.toml with dependencies: notatin, axum 0.8 (multipart), tokio, tower-http, askama, clap 4, serde, uuid, chrono, tracing, open, include_dir
Create src/main.rs — CLI args (--path, --port, --open), tokio server setup
Create src/state.rs — AppState (HashMap of HiveEntry), HiveEntry (id, name, data bytes, size)
Create src/routes/mod.rs — Router with all routes + embedded static file serving
Create src/routes/pages.rs — Serves index.html template
Create templates/index.html — Full HTML shell with toolbar, sidebar, split-pane layout
Create static/style.css — Complete dark theme CSS (Windows 10/11 regedit inspired)
Vendor static/htmx.min.js
Create static/app.js — Split-pane resize, drag-drop, tree toggle, keyboard navigation
Create askama.toml — Point template dir to templates/
Phase 2: Registry Parsing Core
Create src/registry.rs:
create_parser(entry: &HiveEntry) -> Result<Parser> — Creates parser from Cursor<Vec<u8>>
load_hive_from_path(path) -> Result<HiveEntry> — Reads file + auto-discovers .LOG1/.LOG2
get_root_children(entry) -> Result<(root_path, Vec<KeyChild>)>
get_children_at_path(entry, path) -> Result<Vec<KeyChild>>
get_values_at_path(entry, path) -> Result<(KeyInfo, Vec<RegValue>)>
search_hive(entry, query, max_results) -> Result<Vec<SearchResult>>
Phase 3: API Routes + htmx Templates
Create src/routes/hives.rs — File upload (multipart), list hives, delete hive
Create src/routes/keys.rs — Lazy-load tree children as HTML fragments
Create src/routes/values.rs — Return value table as HTML fragment
Create src/routes/search.rs — Search keys/values, return results fragment
Create templates/hive_list.html — Sidebar hive items with click-to-load
Create templates/tree_children.html — Recursive tree nodes with htmx expand/collapse
Create templates/detail_panel.html — Value table (Name, Type, Data) with key metadata header
Create templates/search_results.html — Clickable search results
Phase 4: Polish & Edge Cases
Binary data hex display for REG_BINARY values
Deleted key styling (red tint)
Address/breadcrumb bar showing current path
Test with large hives (SOFTWARE, SYSTEM) for performance
Error handling for corrupt/invalid hive files
UI Design (Dark Theme)
Colors: Background #1e1e1e, panels #252526, hover #2d2d2d, text #cccccc, accent #0078d4 (Windows blue), selection #094771, borders #3e3e42
Tree: Nested <ul>/<li>, 16px indent, ▶/▼ expand arrows, folder icons, value counts
Detail table: Sticky header, Name/Type/Data columns, type icons (ab for strings, 01 for binary, # for numbers)
Split-pane: Draggable resize handle, 35%/65% default split
Verification
cargo build — Compiles without errors
cargo run -- --port 8080 — Serves at localhost:8080, shows empty state
Upload a NTUSER.DAT via drag-drop or file picker — Appears in sidebar
Click hive in sidebar — Tree root loads with child keys
Click expand arrow — Children lazy-load via htmx
Click key name — Detail panel shows values with Name, Type, Data
Search for a key/value name — Results appear and are clickable
cargo run -- --path /path/to/SYSTEM --open — Pre-loads hive and opens browser