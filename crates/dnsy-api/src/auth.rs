//! Authentication and authorisation for API handlers.
//!
//! A handler takes `RequireScope<Read>`, `RequireScope<Write>` or `RequireScope<AdminScope>`.
//! Credentials, in order: `Authorization: Bearer <token>`, then the `dnsy_session` cookie
//! (`__Host-dnsy_session` when cookies are `Secure`).
//! Cookie credentials on unsafe methods must also carry an `X-CSRF-Token` header equal to
//! the `dnsy_csrf` cookie (double submit). Bearer requests need no CSRF token.
//!
//! All credential handling lives in [`Authenticator::authenticate`], the single place to
//! extend (per-username throttling, session invalidation on password change).

use std::marker::PhantomData;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, header};
use dnsy_auth::TokenVerifier;
use dnsy_core::{Role, Scope, TokenId, UserId};
use subtle::ConstantTimeEq;

use crate::error::ApiError;
use crate::state::ApiState;

pub const SESSION_COOKIE: &str = "dnsy_session";
pub const CSRF_COOKIE: &str = "dnsy_csrf";

/// Name of the session cookie: `__Host-dnsy_session` when cookies are `Secure`, else
/// `dnsy_session`. The `__Host-` prefix makes browsers refuse a cookie that is not `Secure`,
/// has a `Domain` or a `Path` other than `/`.
#[must_use]
pub fn session_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-dnsy_session"
    } else {
        SESSION_COOKIE
    }
}

/// Name of the CSRF cookie: `__Host-dnsy_csrf` when cookies are `Secure`, else `dnsy_csrf`.
#[must_use]
pub fn csrf_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-dnsy_csrf"
    } else {
        CSRF_COOKIE
    }
}
pub const CSRF_HEADER: &str = "x-csrf-token";

/// The client address of a request, as an `axum` extension set by the listener: the TCP peer,
/// or the `X-Forwarded-For` client when the peer is a trusted proxy (`[api] trusted_proxies`).
/// The login throttle and the known-client exemption are keyed on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddr(pub std::net::IpAddr);

/// How a request proved who it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Token(TokenId),
    Session,
}

/// The authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUser {
    pub user: UserId,
    pub role: Role,
    pub method: AuthMethod,
}

/// Marker for a scope, so the requirement is visible in a handler's signature.
pub trait ScopeMarker {
    const SCOPE: Scope;
}

/// `api:read`.
pub struct Read;
/// `api:write`.
pub struct Write;
/// `admin`.
pub struct AdminScope;

impl ScopeMarker for Read {
    const SCOPE: Scope = Scope::ApiRead;
}
impl ScopeMarker for Write {
    const SCOPE: Scope = Scope::ApiWrite;
}
impl ScopeMarker for AdminScope {
    const SCOPE: Scope = Scope::Admin;
}

/// Extractor: authenticated caller holding scope `S` (token scope or role permission).
pub struct RequireScope<S: ScopeMarker>(pub AuthUser, PhantomData<S>);

impl<S: ScopeMarker, T> FromRequestParts<T> for RequireScope<S>
where
    ApiState: FromRef<T>,
    T: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &T) -> Result<Self, ApiError> {
        let state = ApiState::from_ref(state);
        let user = Authenticator::new(&state)
            .authenticate(&parts.headers, &parts.method, S::SCOPE)
            .await?;
        Ok(RequireScope(user, PhantomData))
    }
}

/// Resolves credentials to an [`AuthUser`].
pub struct Authenticator<'a> {
    state: &'a ApiState,
}

impl<'a> Authenticator<'a> {
    #[must_use]
    pub fn new(state: &'a ApiState) -> Authenticator<'a> {
        Authenticator { state }
    }

    /// # Errors
    /// 401 without or with bad credentials, 403 for a missing scope or CSRF mismatch.
    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
        method: &Method,
        needed: Scope,
    ) -> Result<AuthUser, ApiError> {
        if let Some(value) = headers.get(header::AUTHORIZATION) {
            let token = value
                .to_str()
                .ok()
                .and_then(|v| {
                    let (scheme, rest) = v.split_once(' ')?;
                    scheme.eq_ignore_ascii_case("bearer").then_some(rest.trim())
                })
                .ok_or(ApiError::Unauthorized)?;
            return self.by_token(token, needed).await;
        }
        let session = cookie(headers, session_cookie_name(self.state.auth.cookie_secure))
            .ok_or(ApiError::Unauthorized)?;
        self.by_session(session, headers, method, needed).await
    }

    async fn by_token(&self, token: &str, needed: Scope) -> Result<AuthUser, ApiError> {
        let principal = self.state.auth.tokens.verify(token, needed).await?;
        let dnsy_core::Principal::Token { token, user } = principal else {
            return Err(ApiError::Unauthorized);
        };
        let role = self.state.auth.users.get(user).await?.role;
        if !role.allows(needed) {
            return Err(ApiError::Forbidden("the role lacks the required scope"));
        }
        Ok(AuthUser {
            user,
            role,
            method: AuthMethod::Token(token),
        })
    }

    async fn by_session(
        &self,
        id: &str,
        headers: &HeaderMap,
        method: &Method,
        needed: Scope,
    ) -> Result<AuthUser, ApiError> {
        let session = self.state.auth.sessions.validate(id).await?;
        let user = self.state.auth.users.get(session.user).await?;
        if !user.role.allows(needed) {
            return Err(ApiError::Forbidden("the role lacks the required scope"));
        }
        if !is_safe(method) && !csrf_matches(headers, self.state.auth.cookie_secure) {
            return Err(ApiError::Forbidden("missing or invalid CSRF token"));
        }
        Ok(AuthUser {
            user: user.id,
            role: user.role,
            method: AuthMethod::Session,
        })
    }
}

fn is_safe(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn csrf_matches(headers: &HeaderMap, secure: bool) -> bool {
    let (Some(cookie_value), Some(header_value)) = (
        cookie(headers, csrf_cookie_name(secure)),
        headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()),
    ) else {
        return false;
    };
    !cookie_value.is_empty() && bool::from(cookie_value.as_bytes().ct_eq(header_value.as_bytes()))
}

/// Value of cookie `name` from the `Cookie` header(s).
pub(crate) fn cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k.trim() == name).then(|| v.trim())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_parsing() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "a=1; dnsy_csrf=tok; b=2".parse().unwrap());
        assert_eq!(cookie(&h, "dnsy_csrf"), Some("tok"));
        assert_eq!(cookie(&h, "c"), None);
    }

    #[test]
    fn csrf_requires_both_and_equal() {
        let mut h = HeaderMap::new();
        assert!(!csrf_matches(&h, false));
        h.insert(header::COOKIE, "dnsy_csrf=tok".parse().unwrap());
        assert!(!csrf_matches(&h, false));
        h.insert(CSRF_HEADER, "other".parse().unwrap());
        assert!(!csrf_matches(&h, false));
        h.insert(CSRF_HEADER, "tok".parse().unwrap());
        assert!(csrf_matches(&h, false));
    }
}
