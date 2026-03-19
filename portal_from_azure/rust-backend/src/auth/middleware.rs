/// Auth middleware / extractors – mirrors app/dependencies.py
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use std::sync::Arc;

use crate::auth::security::decode_token;
use crate::database::{Database, User};
use crate::ioc::IpsumData;
use tokio::sync::RwLock;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub templates: Arc<tera::Tera>,
    pub ipsum: Arc<RwLock<IpsumData>>,
}

// ── Authenticated user extractor (redirects to login) ─────

pub struct AuthUser(pub User);

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get("access_token")
            .map(|c| c.value().to_string())
            .unwrap_or_default();

        let token = token.strip_prefix("Bearer ").unwrap_or(&token);
        if token.is_empty() {
            return Err(Redirect::to("/auth/login").into_response());
        }

        let username =
            decode_token(token).ok_or_else(|| Redirect::to("/auth/login").into_response())?;

        let user = state
            .db
            .get_user(&username)
            .ok_or_else(|| Redirect::to("/auth/login").into_response())?;

        if user.disabled {
            return Err(Redirect::to("/auth/login").into_response());
        }

        Ok(AuthUser(user))
    }
}

// ── Admin user extractor ───────────────────────────────────

pub struct AdminUser(pub User);

impl FromRequestParts<Arc<AppState>> for AdminUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let AuthUser(user) = AuthUser::from_request_parts(parts, state).await?;
        if !user.is_admin {
            return Err((StatusCode::FORBIDDEN, "Admin access required").into_response());
        }
        Ok(AdminUser(user))
    }
}

// ── Optional user extractor (for login page check) ────────

pub struct MaybeUser(pub Option<User>);

impl FromRequestParts<Arc<AppState>> for MaybeUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get("access_token")
            .map(|c| c.value().to_string())
            .unwrap_or_default();
        let token = token.strip_prefix("Bearer ").unwrap_or(&token);
        if token.is_empty() {
            return Ok(MaybeUser(None));
        }

        let username = match decode_token(token) {
            Some(u) => u,
            None => return Ok(MaybeUser(None)),
        };

        Ok(MaybeUser(state.db.get_user(&username)))
    }
}
