/// Admin routes – mirrors app/routers/admin.py
use axum::{
    Json, Router,
    extract::{Form, Path as AxPath, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, patch, post},
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::middleware::{AdminUser, AppState};
use crate::auth::security::hash_password;
use crate::template_utils;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Web interface
        .route("/admin/panel", get(admin_panel))
        .route("/admin/panel/add-user", post(add_user_web))
        .route("/admin/panel/delete-user/{username}", post(delete_user_web))
        .route("/admin/panel/make-admin/{username}", post(make_admin_web))
        .route(
            "/admin/panel/revoke-admin/{username}",
            post(revoke_admin_web),
        )
        // API
        .route("/admin/users", get(list_users_api).post(create_user_api))
        .route(
            "/admin/users/{username}",
            delete(delete_user_api).patch(update_user_api),
        )
        .route("/admin/users/{username}/make-admin", post(grant_admin_api))
        .route(
            "/admin/users/{username}/revoke-admin",
            post(revoke_admin_api),
        )
}

fn user_json(u: &crate::database::User) -> serde_json::Value {
    serde_json::json!({
        "username": u.username,
        "email": u.email,
        "full_name": u.full_name,
        "disabled": u.disabled,
        "is_admin": u.is_admin,
    })
}

// ── Web: panel ──────────────────────────────────────────────

#[derive(Deserialize)]
struct PanelQuery {
    success: Option<String>,
    error: Option<String>,
}

async fn admin_panel(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    axum::extract::Query(q): axum::extract::Query<PanelQuery>,
) -> Html<String> {
    let users: Vec<serde_json::Value> = state
        .db
        .get_all_users()
        .iter()
        .map(|u| user_json(u))
        .collect();
    let mut ctx = tera::Context::new();
    ctx.insert("user", &user_json(&admin));
    ctx.insert(
        "avatar_letter",
        &template_utils::avatar_letter(&admin.username),
    );
    ctx.insert("users", &users);
    ctx.insert("success", &q.success);
    ctx.insert("error", &q.error);
    template_utils::render(&state.templates, "admin.html", &ctx)
}

// ── Web: add user ───────────────────────────────────────────

#[derive(Deserialize)]
struct AddUserForm {
    username: String,
    password: String,
    email: Option<String>,
    full_name: Option<String>,
    is_admin: Option<String>,
}

async fn add_user_web(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    Form(form): Form<AddUserForm>,
) -> Redirect {
    if state.db.user_exists(&form.username) {
        return Redirect::to(&format!(
            "/admin/panel?error=User '{}' already exists",
            form.username
        ));
    }
    let hashed = hash_password(&form.password);
    let is_admin = form.is_admin.as_deref() == Some("true");
    match state.db.create_user(
        &form.username,
        &hashed,
        form.email.as_deref(),
        form.full_name.as_deref(),
        is_admin,
    ) {
        Ok(_) => {
            tracing::info!(admin = %admin.username, target_user = %form.username, is_admin, event = "admin.user_created", "user created");
            Redirect::to(&format!(
                "/admin/panel?success=User '{}' created successfully",
                form.username
            ))
        }
        Err(e) => Redirect::to(&format!("/admin/panel?error=Failed to create user: {}", e)),
    }
}

// ── Web: delete user ────────────────────────────────────────

async fn delete_user_web(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    AxPath(username): AxPath<String>,
) -> Redirect {
    if username == admin.username {
        return Redirect::to("/admin/panel?error=Cannot delete your own account");
    }
    if !state.db.user_exists(&username) {
        return Redirect::to(&format!("/admin/panel?error=User '{}' not found", username));
    }
    if state.db.delete_user(&username) {
        tracing::info!(admin = %admin.username, target_user = %username, event = "admin.user_deleted", "user deleted");
        Redirect::to(&format!(
            "/admin/panel?success=User '{}' deleted successfully",
            username
        ))
    } else {
        Redirect::to(&format!(
            "/admin/panel?error=Failed to delete user '{}'",
            username
        ))
    }
}

// ── Web: make admin ─────────────────────────────────────────

async fn make_admin_web(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    AxPath(username): AxPath<String>,
) -> Redirect {
    if !state.db.user_exists(&username) {
        return Redirect::to(&format!("/admin/panel?error=User '{}' not found", username));
    }
    if state.db.update_admin_status(&username, true) {
        tracing::info!(admin = %admin.username, target_user = %username, event = "admin.admin_granted", "admin privileges granted");
        Redirect::to(&format!(
            "/admin/panel?success=Admin privileges granted to '{}'",
            username
        ))
    } else {
        Redirect::to(&format!(
            "/admin/panel?error=Failed to grant admin access to '{}'",
            username
        ))
    }
}

// ── Web: revoke admin ───────────────────────────────────────

async fn revoke_admin_web(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    AxPath(username): AxPath<String>,
) -> Redirect {
    if username == admin.username {
        return Redirect::to("/admin/panel?error=Cannot revoke your own admin access");
    }
    if !state.db.user_exists(&username) {
        return Redirect::to(&format!("/admin/panel?error=User '{}' not found", username));
    }
    if state.db.update_admin_status(&username, false) {
        tracing::info!(admin = %admin.username, target_user = %username, event = "admin.admin_revoked", "admin privileges revoked");
        Redirect::to(&format!(
            "/admin/panel?success=Admin privileges revoked from '{}'",
            username
        ))
    } else {
        Redirect::to(&format!(
            "/admin/panel?error=Failed to revoke admin access from '{}'",
            username
        ))
    }
}

// ── API: list users ─────────────────────────────────────────

async fn list_users_api(
    State(state): State<Arc<AppState>>,
    AdminUser(_admin): AdminUser,
) -> Json<Vec<serde_json::Value>> {
    Json(
        state
            .db
            .get_all_users()
            .iter()
            .map(|u| user_json(u))
            .collect(),
    )
}

// ── API: create user ────────────────────────────────────────

#[derive(Deserialize)]
struct CreateUserJson {
    username: String,
    password: String,
    email: Option<String>,
    full_name: Option<String>,
    is_admin: Option<bool>,
}

async fn create_user_api(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    Json(body): Json<CreateUserJson>,
) -> Response {
    if state.db.user_exists(&body.username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": format!("User '{}' already exists", body.username)})),
        )
            .into_response();
    }
    let hashed = hash_password(&body.password);
    match state.db.create_user(
        &body.username,
        &hashed,
        body.email.as_deref(),
        body.full_name.as_deref(),
        body.is_admin.unwrap_or(false),
    ) {
        Ok(u) => {
            tracing::info!(admin = %admin.username, target_user = %body.username, is_admin = body.is_admin.unwrap_or(false), event = "admin.user_created", "user created via API");
            (StatusCode::CREATED, Json(user_json(&u))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"detail": e.to_string()})),
        )
            .into_response(),
    }
}

// ── API: delete user ────────────────────────────────────────

async fn delete_user_api(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    AxPath(username): AxPath<String>,
) -> Response {
    if username == admin.username {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail":"Cannot delete your own account"})),
        )
            .into_response();
    }
    if !state.db.user_exists(&username) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": format!("User '{}' not found", username)})),
        )
            .into_response();
    }
    if state.db.delete_user(&username) {
        tracing::info!(admin = %admin.username, target_user = %username, event = "admin.user_deleted", "user deleted via API");
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"detail":"Failed to delete user"})),
        )
            .into_response()
    }
}

// ── API: update user ────────────────────────────────────────

#[derive(Deserialize)]
struct UpdateUserJson {
    email: Option<String>,
    full_name: Option<String>,
    disabled: Option<bool>,
    is_admin: Option<bool>,
}

async fn update_user_api(
    State(state): State<Arc<AppState>>,
    AdminUser(_admin): AdminUser,
    AxPath(username): AxPath<String>,
    Json(body): Json<UpdateUserJson>,
) -> Response {
    if !state.db.user_exists(&username) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": format!("User '{}' not found", username)})),
        )
            .into_response();
    }
    match state.db.update_user(
        &username,
        body.email.as_deref(),
        body.full_name.as_deref(),
        body.disabled,
        body.is_admin,
    ) {
        Some(u) => Json(user_json(&u)).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"detail":"Failed to update user"})),
        )
            .into_response(),
    }
}

// ── API: grant/revoke admin ─────────────────────────────────

async fn grant_admin_api(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    AxPath(username): AxPath<String>,
) -> Response {
    if !state.db.user_exists(&username) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": format!("User '{}' not found", username)})),
        )
            .into_response();
    }
    if !state.db.update_admin_status(&username, true) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"detail":"Failed to grant admin access"})),
        )
            .into_response();
    }
    tracing::info!(admin = %admin.username, target_user = %username, event = "admin.admin_granted", "admin privileges granted via API");
    let u = state.db.get_user(&username).unwrap();
    Json(user_json(&u)).into_response()
}

async fn revoke_admin_api(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    AxPath(username): AxPath<String>,
) -> Response {
    if username == admin.username {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail":"Cannot revoke your own admin access"})),
        )
            .into_response();
    }
    if !state.db.user_exists(&username) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": format!("User '{}' not found", username)})),
        )
            .into_response();
    }
    if !state.db.update_admin_status(&username, false) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"detail":"Failed to revoke admin access"})),
        )
            .into_response();
    }
    tracing::info!(admin = %admin.username, target_user = %username, event = "admin.admin_revoked", "admin privileges revoked via API");
    let u = state.db.get_user(&username).unwrap();
    Json(user_json(&u)).into_response()
}
