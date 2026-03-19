/// Auth routes – mirrors app/auth/router.py
use axum::{
    Router,
    extract::{Form, State},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::middleware::{AppState, AuthUser, MaybeUser};
use crate::auth::security::{create_access_token, hash_password, verify_password};
use crate::config::ACCESS_TOKEN_EXPIRE_MINUTES;
use crate::template_utils;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/login", get(login_page).post(login_submit))
        .route("/auth/token", post(login_token))
        .route("/auth/logout", get(logout))
        .route(
            "/auth/change-password",
            get(change_password_page).post(change_password_submit),
        )
}

// ── Login page ──────────────────────────────────────────────

async fn login_page(State(state): State<Arc<AppState>>, maybe: MaybeUser) -> Response {
    if maybe.0.is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    let mut ctx = tera::Context::new();
    ctx.insert("error", &tera::Value::Null);
    template_utils::render(&state.templates, "login.html", &ctx).into_response()
}

// ── Login submit ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

async fn login_submit(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    let user = state.db.get_user(&form.username);
    let valid = user
        .as_ref()
        .map(|u| verify_password(&form.password, &u.hashed_password))
        .unwrap_or(false);

    if !valid {
        tracing::warn!(user = %form.username, event = "auth.login_failed", "login attempt failed");
        let mut ctx = tera::Context::new();
        ctx.insert("error", "Invalid username or password");
        return template_utils::render(&state.templates, "login.html", &ctx).into_response();
    }

    tracing::info!(user = %form.username, event = "auth.login_success", "user logged in");
    let token = create_access_token(&form.username, None);
    let cookie = Cookie::build(("access_token", format!("Bearer {}", token)))
        .path("/")
        .http_only(true)
        .max_age(time::Duration::minutes(ACCESS_TOKEN_EXPIRE_MINUTES))
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .build();

    (jar.add(cookie), Redirect::to("/dashboard")).into_response()
}

// ── OAuth2 token endpoint ──────────────────────────────────

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct TokenForm {
    username: String,
    password: String,
    grant_type: Option<String>,
}

async fn login_token(State(state): State<Arc<AppState>>, Form(form): Form<TokenForm>) -> Response {
    let user = state.db.get_user(&form.username);
    let valid = user
        .as_ref()
        .map(|u| verify_password(&form.password, &u.hashed_password))
        .unwrap_or(false);

    if !valid {
        tracing::warn!(user = %form.username, event = "auth.token_failed", "API token request failed");
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"detail": "Incorrect username or password"})),
        )
            .into_response();
    }

    tracing::info!(user = %form.username, event = "auth.token_issued", "API token issued");
    let token = create_access_token(&form.username, None);
    axum::Json(serde_json::json!({
        "access_token": token,
        "token_type": "bearer"
    }))
    .into_response()
}

// ── Logout ──────────────────────────────────────────────────

async fn logout(jar: CookieJar) -> impl IntoResponse {
    // Decode username from JWT for audit log — no DB hit needed
    let username = jar
        .get("access_token")
        .and_then(|c| c.value().strip_prefix("Bearer ").map(String::from))
        .and_then(|t| crate::auth::security::decode_token(&t))
        .unwrap_or_else(|| "unknown".to_string());
    tracing::info!(user = %username, event = "auth.logout", "user logged out");
    let removal = Cookie::build(("access_token", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .build();
    (jar.remove(removal), Redirect::to("/auth/login"))
}

// ── Change password page ────────────────────────────────────

async fn change_password_page(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
) -> Html<String> {
    let mut ctx = tera::Context::new();
    ctx.insert(
        "user",
        &serde_json::json!({
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
        }),
    );
    ctx.insert("error", &tera::Value::Null);
    ctx.insert("success", &tera::Value::Null);
    template_utils::render(&state.templates, "change_password.html", &ctx)
}

// ── Change password submit ──────────────────────────────────

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
}

async fn change_password_submit(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    Form(form): Form<ChangePasswordForm>,
) -> Html<String> {
    let mut ctx = tera::Context::new();
    ctx.insert(
        "user",
        &serde_json::json!({
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
        }),
    );

    // Validate current password
    if !verify_password(&form.current_password, &user.hashed_password) {
        ctx.insert("error", "Current password is incorrect");
        ctx.insert("success", &tera::Value::Null);
        return template_utils::render(&state.templates, "change_password.html", &ctx);
    }

    // Validate new password
    let np = &form.new_password;
    let err = if np.len() < 8 {
        Some("Password must be at least 8 characters")
    } else if !np.chars().any(|c| c.is_alphabetic()) {
        Some("Password must contain at least one letter")
    } else if !np.chars().any(|c| c.is_ascii_digit()) {
        Some("Password must contain at least one number")
    } else if !np.chars().any(|c| !c.is_alphanumeric()) {
        Some("Password must contain at least one special character")
    } else if np != &form.confirm_password {
        Some("New passwords do not match")
    } else {
        None
    };

    if let Some(e) = err {
        ctx.insert("error", e);
        ctx.insert("success", &tera::Value::Null);
        return template_utils::render(&state.templates, "change_password.html", &ctx);
    }

    let hashed = hash_password(np);
    if state.db.update_password(&user.username, &hashed) {
        tracing::info!(user = %user.username, event = "auth.password_changed", "password changed successfully");
        ctx.insert("error", &tera::Value::Null);
        ctx.insert("success", "Password changed successfully!");
    } else {
        tracing::warn!(user = %user.username, event = "auth.password_change_failed", "database error on password change");
        ctx.insert("error", "Failed to change password");
        ctx.insert("success", &tera::Value::Null);
    }
    template_utils::render(&state.templates, "change_password.html", &ctx)
}
