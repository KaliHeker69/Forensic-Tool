/// Server Terminal – WebSocket-based interactive shell (admin only)
///
/// GET  /tools/terminal     → renders the terminal HTML page
/// GET  /tools/terminal/ws  → WebSocket upgrade → PTY bridge
use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::{Html, IntoResponse},
    routing::get,
};
use std::sync::Arc;

use crate::auth::middleware::{AdminUser, AppState};
use crate::config::INACTIVITY_TIMEOUT_MINUTES;
use crate::template_utils;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/tools/terminal", get(terminal_page))
        .route("/tools/terminal/ws", get(ws_upgrade))
}

// ── HTML page ──────────────────────────────────────────────

async fn terminal_page(
    State(state): State<Arc<AppState>>,
    AdminUser(user): AdminUser,
) -> Html<String> {
    let mut ctx = tera::Context::new();
    ctx.insert(
        "user",
        &serde_json::json!({
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": user.is_admin,
        }),
    );
    ctx.insert(
        "avatar_letter",
        &template_utils::avatar_letter(&user.username),
    );
    ctx.insert("inactivity_timeout", &INACTIVITY_TIMEOUT_MINUTES);
    template_utils::render(&state.templates, "terminal.html", &ctx)
}

// ── WebSocket upgrade ──────────────────────────────────────

async fn ws_upgrade(ws: WebSocketUpgrade, AdminUser(_user): AdminUser) -> impl IntoResponse {
    ws.on_upgrade(handle_ws)
}

// ── WebSocket ↔ PTY bridge ─────────────────────────────────

async fn handle_ws(mut socket: WebSocket) {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use std::io::{Read, Write};

    // 1. Allocate PTY
    let pty_system = native_pty_system();

    let pty_pair = match pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    }) {
        Ok(pair) => pair,
        Err(e) => {
            let _ = socket
                .send(Message::Text(format!("Failed to allocate PTY: {e}").into()))
                .await;
            return;
        }
    };

    // 2. Spawn shell
    let mut cmd = CommandBuilder::new("/bin/bash");
    cmd.env("TERM", "xterm-256color");

    let mut child = match pty_pair.slave.spawn_command(cmd) {
        Ok(child) => child,
        Err(e) => {
            let _ = socket
                .send(Message::Text(format!("Failed to spawn shell: {e}").into()))
                .await;
            return;
        }
    };

    // We must drop the slave or reads on the master will block forever after
    // the child exits.
    drop(pty_pair.slave);

    let mut reader = pty_pair.master.try_clone_reader().unwrap();
    let writer = pty_pair.master.take_writer().unwrap();
    // Wrap in Arc<Mutex> so we can share the writer with the async task
    let writer = std::sync::Arc::new(std::sync::Mutex::new(writer));

    // 3. PTY stdout → WebSocket (runs in a blocking thread because PTY I/O is sync)
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // Blocking reader task
    let reader_handle = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // 4. Bidirectional bridge
    loop {
        tokio::select! {
            // Data from PTY → send to browser
            recv_result = rx.recv() => {
                match recv_result {
                    Some(data) => {
                        let text = String::from_utf8_lossy(&data).into_owned();
                        if socket.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            // Data from browser → write to PTY
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let s: &str = &text;
                        // Handle terminal resize messages
                        if let Some(resize) = s.strip_prefix("\x1b[8;") {
                            if let Some((rows, cols)) = parse_resize(resize) {
                                let _ = pty_pair.master.resize(PtySize {
                                    rows,
                                    cols,
                                    pixel_width: 0,
                                    pixel_height: 0,
                                });
                                continue;
                            }
                        }
                        let w = writer.clone();
                        if let Ok(mut w) = w.lock() {
                            if w.write_all(s.as_bytes()).is_err() {
                                break;
                            }
                            let _ = w.flush();
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        let w = writer.clone();
                        if let Ok(mut w) = w.lock() {
                            if w.write_all(&data).is_err() {
                                break;
                            }
                            let _ = w.flush();
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    // 5. Cleanup
    let _ = child.kill();
    let _ = child.wait();
    reader_handle.abort();
}

/// Parse a resize escape: expects `<rows>;<cols>t` after the prefix has been stripped.
fn parse_resize(s: &str) -> Option<(u16, u16)> {
    let s = s.strip_suffix('t')?;
    let mut parts = s.split(';');
    let rows: u16 = parts.next()?.parse().ok()?;
    let cols: u16 = parts.next()?.parse().ok()?;
    Some((rows, cols))
}
