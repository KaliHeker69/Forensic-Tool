/// JWT + bcrypt security helpers – mirrors app/auth/security.py
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::config::{ACCESS_TOKEN_EXPIRE_MINUTES, secret_key};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
}

/// Create a signed JWT.
pub fn create_access_token(username: &str, expire_minutes: Option<i64>) -> String {
    let exp = Utc::now() + Duration::minutes(expire_minutes.unwrap_or(ACCESS_TOKEN_EXPIRE_MINUTES));
    let claims = Claims {
        sub: username.to_string(),
        exp: exp.timestamp(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key().as_bytes()),
    )
    .expect("JWT encoding failed")
}

/// Decode and validate a JWT, returning the username (`sub`).
pub fn decode_token(token: &str) -> Option<String> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret_key().as_bytes()),
        &Validation::default(),
    )
    .ok()
    .map(|data| data.claims.sub)
}

/// Hash a password with bcrypt (cost 12).
pub fn hash_password(password: &str) -> String {
    // Truncate to 72 bytes like the Python backend does
    let truncated: String = password.chars().collect::<String>();
    let bytes = truncated.as_bytes();
    let slice = &bytes[..bytes.len().min(72)];
    bcrypt::hash(std::str::from_utf8(slice).unwrap_or(password), 12).expect("bcrypt hash failed")
}

/// Verify a plain password against a bcrypt hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let bytes = password.as_bytes();
    let slice = &bytes[..bytes.len().min(72)];
    bcrypt::verify(std::str::from_utf8(slice).unwrap_or(password), hash).unwrap_or(false)
}
