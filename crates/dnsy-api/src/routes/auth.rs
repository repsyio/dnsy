//! Login, logout, current user, first-admin bootstrap and password change.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{AppendHeaders, IntoResponse};
use axum::{Extension, Json};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dnsy_auth::ABSOLUTE_TIMEOUT_SECS;
use dnsy_core::Role;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::users::{UserInfo, check_password};
use crate::auth::{
    AuthMethod, CSRF_COOKIE, ClientAddr, Read, RequireScope, SESSION_COOKIE, cookie,
};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

/// Credentials.
#[derive(Deserialize, ToSchema)]
pub struct Login {
    pub username: String,
    pub password: String,
}

/// The caller as seen by `GET /auth/me`.
#[derive(Serialize, ToSchema)]
pub struct Me {
    #[serde(flatten)]
    pub user: UserInfo,
    /// `session` or `token`.
    pub auth: &'static str,
}

/// First-admin creation.
#[derive(Deserialize, ToSchema)]
pub struct Bootstrap {
    /// The one-time code printed to stderr at startup.
    pub code: String,
    pub username: String,
    /// At least 8 characters.
    pub password: String,
}

/// Password change.
#[derive(Deserialize, ToSchema)]
pub struct ChangePassword {
    pub current_password: String,
    /// At least 8 characters.
    pub new_password: String,
}

/// Routes relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(login))
        .routes(routes!(logout))
        .routes(routes!(me))
        .routes(routes!(bootstrap))
        .routes(routes!(change_password))
}

/// The client address the listener resolved ([`ClientAddr`]), else the peer address, or an
/// internal error: without either the throttle would key everyone together.
fn client_ip(
    client: Option<Extension<ClientAddr>>,
    info: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<IpAddr, ApiError> {
    client
        .map(|Extension(ClientAddr(ip))| ip)
        .or_else(|| info.map(|Extension(ConnectInfo(a))| a.ip()))
        .ok_or_else(|| ApiError::Internal("the server did not provide the peer address".to_owned()))
}

fn cookie_header(
    name: &str,
    value: &str,
    max_age: i64,
    http_only: bool,
    secure: bool,
) -> HeaderValue {
    let mut v = format!("{name}={value}; Path=/; SameSite=Strict; Max-Age={max_age}");
    if http_only {
        v.push_str("; HttpOnly");
    }
    if secure {
        v.push_str("; Secure");
    }
    HeaderValue::from_str(&v).expect("cookie values are ASCII without control characters")
}

/// `Set-Cookie` pair establishing a session and a fresh CSRF token.
fn session_cookies(
    state: &ApiState,
    session: &str,
) -> AppendHeaders<[(axum::http::HeaderName, HeaderValue); 2]> {
    let mut raw = [0u8; 32];
    rand::fill(&mut raw[..]);
    let csrf = URL_SAFE_NO_PAD.encode(raw);
    AppendHeaders([
        (
            SET_COOKIE,
            cookie_header(
                SESSION_COOKIE,
                session,
                ABSOLUTE_TIMEOUT_SECS,
                true,
                state.auth.cookie_secure,
            ),
        ),
        (
            SET_COOKIE,
            cookie_header(
                CSRF_COOKIE,
                &csrf,
                ABSOLUTE_TIMEOUT_SECS,
                false,
                state.auth.cookie_secure,
            ),
        ),
    ])
}

fn clear_cookies(state: &ApiState) -> AppendHeaders<[(axum::http::HeaderName, HeaderValue); 2]> {
    AppendHeaders([
        (
            SET_COOKIE,
            cookie_header(SESSION_COOKIE, "", 0, true, state.auth.cookie_secure),
        ),
        (
            SET_COOKIE,
            cookie_header(CSRF_COOKIE, "", 0, false, state.auth.cookie_secure),
        ),
    ])
}

/// Log in with username and password; sets the session and CSRF cookies.
#[utoipa::path(post, path = "/auth/login", tag = "auth", request_body = Login,
    responses(
        (status = 200, description = "Logged in; `dnsy_session` (HttpOnly) and `dnsy_csrf` cookies set", body = UserInfo),
        (status = 401, description = "Wrong username or password", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "Too many failed logins", body = Problem, content_type = "application/problem+json"),
    ))]
async fn login(
    State(state): State<ApiState>,
    client: Option<Extension<ClientAddr>>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<Login>,
) -> Result<impl IntoResponse, ApiError> {
    let previous = cookie(&headers, SESSION_COOKIE);
    let (session, user) = state
        .auth
        .sessions
        .login(
            &state.auth.users,
            &body.username,
            &body.password,
            client_ip(client, connect)?,
            previous,
        )
        .await?;
    Ok((
        session_cookies(&state, &session),
        Json(UserInfo::from(user)),
    ))
}

/// End the current session and clear the cookies.
#[utoipa::path(post, path = "/auth/logout", tag = "auth", security(("session" = [])),
    responses(
        (status = 204, description = "Logged out"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "CSRF check failed", body = Problem, content_type = "application/problem+json"),
    ))]
async fn logout(
    _: RequireScope<Read>,
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(id) = cookie(&headers, SESSION_COOKIE) {
        state.auth.sessions.destroy(id).await?;
    }
    Ok((StatusCode::NO_CONTENT, clear_cookies(&state)))
}

/// The authenticated caller.
#[utoipa::path(get, path = "/auth/me", tag = "auth", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, body = Me),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    ))]
async fn me(
    scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<Me>, ApiError> {
    let user = state.auth.users.get(scope.0.user).await?;
    let auth = match scope.0.method {
        AuthMethod::Session => "session",
        AuthMethod::Token(_) => "token",
    };
    Ok(Json(Me {
        user: user.into(),
        auth,
    }))
}

/// Create the first admin with the one-time code printed at startup.
#[utoipa::path(post, path = "/auth/bootstrap", tag = "auth", request_body = Bootstrap,
    responses(
        (status = 201, description = "First admin created", body = UserInfo),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Invalid or expired code", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Users already exist", body = Problem, content_type = "application/problem+json"),
    ))]
async fn bootstrap(
    State(state): State<ApiState>,
    Json(body): Json<Bootstrap>,
) -> Result<(StatusCode, Json<UserInfo>), ApiError> {
    if state.auth.users.count().await? > 0 {
        return Err(ApiError::Conflict("bootstrap is already done".to_owned()));
    }
    let Some(code) = &state.auth.bootstrap else {
        return Err(ApiError::Unauthorized);
    };
    check_password(&body.password)?;
    let user = state
        .auth
        .users
        .bootstrap_admin(code, &body.code, &body.username, &body.password)
        .await?;
    debug_assert_eq!(user.role, Role::Admin);
    Ok((StatusCode::CREATED, Json(user.into())))
}

/// Change the caller's password. Ends all sessions and starts a new one for this client. The
/// current password is checked as a login (same throttle, 429 when locked out).
#[utoipa::path(put, path = "/auth/me/password", tag = "auth", security(("session" = [])),
    request_body = ChangePassword,
    responses(
        (status = 200, description = "Changed; new session cookies set", body = UserInfo),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Current password is wrong", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Not a session", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "Too many failed attempts", body = Problem, content_type = "application/problem+json"),
    ))]
async fn change_password(
    scope: RequireScope<Read>,
    State(state): State<ApiState>,
    client: Option<Extension<ClientAddr>>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(body): Json<ChangePassword>,
) -> Result<impl IntoResponse, ApiError> {
    if scope.0.method != AuthMethod::Session {
        return Err(ApiError::Forbidden(
            "the password can only be changed from a session",
        ));
    }
    check_password(&body.new_password)?;
    let ip = client_ip(client, connect)?;
    let user = state.auth.users.get(scope.0.user).await?;
    // The current password goes through the login throttle, so a stolen session cannot be used
    // to guess it without limit. The session this creates is ended by `set_password` below.
    state
        .auth
        .sessions
        .login(
            &state.auth.users,
            &user.username,
            &body.current_password,
            ip,
            None,
        )
        .await?;
    state
        .auth
        .users
        .set_password(user.id, &body.new_password)
        .await?;
    let (session, user) = state
        .auth
        .sessions
        .login(
            &state.auth.users,
            &user.username,
            &body.new_password,
            ip,
            None,
        )
        .await?;
    Ok((
        session_cookies(&state, &session),
        Json(UserInfo::from(user)),
    ))
}
