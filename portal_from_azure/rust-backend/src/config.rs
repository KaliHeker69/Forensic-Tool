/// Application configuration – mirrors app/config.py
use std::env;

pub const APP_NAME: &str = "Resource Portal";
pub const APP_DESCRIPTION: &str = "Secure access portal for cybersecurity resources";

/// JWT
pub fn secret_key() -> String {
    env::var("SECRET_KEY")
        .unwrap_or_else(|_| "dev-secret-key-change-in-production-use-openssl-rand-hex-32".into())
}
pub const ALGORITHM: &str = "HS256"; // used by jsonwebtoken
pub const ACCESS_TOKEN_EXPIRE_MINUTES: i64 = 30;
pub const INACTIVITY_TIMEOUT_MINUTES: i64 = 15;

/// Database
pub fn database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| "portal.db".into())
}
