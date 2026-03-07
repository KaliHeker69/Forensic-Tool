/// Database layer – SQLite via rusqlite.
/// Mirrors app/database.py + app/models.py
use rusqlite::{Connection, params};
use std::sync::Mutex;

use crate::config::database_url;

/// Shared database handle wrapped in a Mutex for thread-safe access.
pub struct Database {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub full_name: Option<String>,
    pub hashed_password: String,
    pub disabled: bool,
    pub is_admin: bool,
    pub created_at: String,
}

impl Database {
    /// Open (or create) the SQLite database and ensure the schema exists.
    pub fn open() -> Self {
        let conn = Connection::open(database_url()).expect("Failed to open SQLite database");
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .expect("Failed to set PRAGMAs");
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    NOT NULL UNIQUE,
                email           TEXT    UNIQUE,
                full_name       TEXT,
                hashed_password TEXT    NOT NULL,
                disabled        INTEGER NOT NULL DEFAULT 0,
                is_admin        INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
            )",
            [],
        )
        .expect("Failed to create users table");
        Database {
            conn: Mutex::new(conn),
        }
    }

    // ── helpers ──────────────────────────────────────────────

    fn row_to_user(row: &rusqlite::Row) -> rusqlite::Result<User> {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            email: row.get(2)?,
            full_name: row.get(3)?,
            hashed_password: row.get(4)?,
            disabled: row.get::<_, i32>(5)? != 0,
            is_admin: row.get::<_, i32>(6)? != 0,
            created_at: row.get(7)?,
        })
    }

    // ── queries ─────────────────────────────────────────────

    pub fn get_user(&self, username: &str) -> Option<User> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, username, email, full_name, hashed_password, disabled, is_admin, created_at FROM users WHERE username = ?1",
            params![username],
            Self::row_to_user,
        )
        .ok()
    }

    pub fn user_exists(&self, username: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT 1 FROM users WHERE username = ?1",
            params![username],
            |_| Ok(()),
        )
        .is_ok()
    }

    pub fn create_user(
        &self,
        username: &str,
        hashed_password: &str,
        email: Option<&str>,
        full_name: Option<&str>,
        is_admin: bool,
    ) -> rusqlite::Result<User> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (username, hashed_password, email, full_name, is_admin) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![username, hashed_password, email, full_name, is_admin as i32],
        )?;
        let id = conn.last_insert_rowid();
        conn.query_row(
            "SELECT id, username, email, full_name, hashed_password, disabled, is_admin, created_at FROM users WHERE id = ?1",
            params![id],
            Self::row_to_user,
        )
    }

    pub fn get_all_users(&self) -> Vec<User> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, username, email, full_name, hashed_password, disabled, is_admin, created_at FROM users")
            .unwrap();
        stmt.query_map([], Self::row_to_user)
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    pub fn delete_user(&self, username: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM users WHERE username = ?1", params![username])
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    pub fn update_password(&self, username: &str, hashed: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE users SET hashed_password = ?1 WHERE username = ?2",
            params![hashed, username],
        )
        .map(|n| n > 0)
        .unwrap_or(false)
    }

    pub fn update_admin_status(&self, username: &str, is_admin: bool) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE users SET is_admin = ?1 WHERE username = ?2",
            params![is_admin as i32, username],
        )
        .map(|n| n > 0)
        .unwrap_or(false)
    }

    pub fn update_user(
        &self,
        username: &str,
        email: Option<&str>,
        full_name: Option<&str>,
        disabled: Option<bool>,
        is_admin: Option<bool>,
    ) -> Option<User> {
        let conn = self.conn.lock().unwrap();
        // Build SET clauses dynamically
        let mut sets: Vec<String> = Vec::new();
        let mut vals: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(e) = email {
            sets.push(format!("email = ?{}", sets.len() + 1));
            vals.push(Box::new(e.to_string()));
        }
        if let Some(f) = full_name {
            sets.push(format!("full_name = ?{}", sets.len() + 1));
            vals.push(Box::new(f.to_string()));
        }
        if let Some(d) = disabled {
            sets.push(format!("disabled = ?{}", sets.len() + 1));
            vals.push(Box::new(d as i32));
        }
        if let Some(a) = is_admin {
            sets.push(format!("is_admin = ?{}", sets.len() + 1));
            vals.push(Box::new(a as i32));
        }
        if sets.is_empty() {
            return self.get_user(username);
        }
        let idx = sets.len() + 1;
        let sql = format!(
            "UPDATE users SET {} WHERE username = ?{}",
            sets.join(", "),
            idx
        );
        vals.push(Box::new(username.to_string()));
        let params: Vec<&dyn rusqlite::types::ToSql> = vals.iter().map(|v| v.as_ref()).collect();
        drop(conn);
        {
            let conn = self.conn.lock().unwrap();
            let _ = conn.execute(&sql, params.as_slice());
        }
        self.get_user(username)
    }
}
