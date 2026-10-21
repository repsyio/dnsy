//! A small client for the REST API (`/api/v1`) that exposes what the tests assert on: status,
//! headers (cookies, `ETag`, `Retry-After`) and the body, with explicit control over which
//! credential a request carries (none, bearer, session with or without the CSRF header).

use std::time::{Duration, Instant};

use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, SET_COOKIE};
use serde_json::{Value, json};

use crate::{DEADLINE, Harness};

/// A logged-in browser session: the two cookie values.
#[derive(Clone, Debug)]
pub struct Session {
    pub id: String,
    pub csrf: String,
}

/// Which credential a request carries.
#[derive(Clone, Copy, Debug)]
pub enum Auth<'a> {
    None,
    Bearer(&'a str),
    /// Session cookie, CSRF cookie and `X-CSRF-Token` header.
    Session(&'a Session),
    /// Session and CSRF cookies but no `X-CSRF-Token` header.
    SessionNoCsrfHeader(&'a Session),
    /// Session cookie and CSRF header, with a different value in the header.
    SessionWrongCsrf(&'a Session),
    /// Only the session cookie (no CSRF cookie, no header).
    SessionCookieOnly(&'a Session),
}

/// A response with the body kept as text.
#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: HeaderMap,
    pub text: String,
}

impl Resp {
    /// The body as JSON (`Null` when it is empty or not JSON).
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// All `Set-Cookie` header values.
    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect()
    }

    /// The `Set-Cookie` line of cookie `name`.
    pub fn cookie_line(&self, name: &str) -> Option<String> {
        let prefix = format!("{name}=");
        self.set_cookies()
            .into_iter()
            .find(|c| c.starts_with(&prefix))
    }

    /// The value of cookie `name` from `Set-Cookie`.
    pub fn cookie_value(&self, name: &str) -> Option<String> {
        let line = self.cookie_line(name)?;
        let value = line.split(';').next()?.split_once('=')?.1.to_owned();
        Some(value)
    }

    /// Asserts an RFC 9457 error with `status` and returns the problem document.
    pub fn problem(&self, status: u16) -> Value {
        assert_eq!(
            self.status, status,
            "unexpected status, body: {}",
            self.text
        );
        assert_eq!(
            self.header("content-type"),
            Some("application/problem+json"),
            "error bodies are problem+json: {}",
            self.text
        );
        let p = self.json();
        assert_eq!(p["status"], status, "{p}");
        for key in ["type", "title", "detail"] {
            assert!(
                p[key].as_str().is_some_and(|s| !s.is_empty()),
                "problem lacks `{key}`: {p}"
            );
        }
        assert!(
            p["type"]
                .as_str()
                .unwrap()
                .starts_with("https://dnsy.dev/problems/"),
            "{p}"
        );
        p
    }

    /// Asserts `status` and returns the JSON body.
    pub fn ok(&self, status: u16) -> Value {
        assert_eq!(
            self.status, status,
            "unexpected status, body: {}",
            self.text
        );
        self.json()
    }
}

/// A request under construction.
pub struct Req<'a> {
    api: &'a Api,
    method: Method,
    url: String,
    auth: Auth<'a>,
    body: Option<(Vec<u8>, &'static str)>,
    headers: Vec<(String, String)>,
}

impl<'a> Req<'a> {
    #[must_use]
    pub fn auth(mut self, auth: Auth<'a>) -> Self {
        self.auth = auth;
        self
    }

    #[must_use]
    pub fn bearer(self, token: &'a str) -> Self {
        self.auth(Auth::Bearer(token))
    }

    #[must_use]
    pub fn json(mut self, body: &Value) -> Self {
        self.body = Some((body.to_string().into_bytes(), "application/json"));
        self
    }

    #[must_use]
    pub fn body(mut self, bytes: Vec<u8>, content_type: &'static str) -> Self {
        self.body = Some((bytes, content_type));
        self
    }

    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    fn build(self) -> reqwest::RequestBuilder {
        let mut b = self.api.http.request(self.method, self.url);
        let mut cookies: Vec<String> = Vec::new();
        match self.auth {
            Auth::None => {}
            Auth::Bearer(t) => b = b.bearer_auth(t),
            Auth::Session(s) => {
                cookies.push(format!("dnsy_session={}; dnsy_csrf={}", s.id, s.csrf));
                b = b.header("x-csrf-token", &s.csrf);
            }
            Auth::SessionNoCsrfHeader(s) => {
                cookies.push(format!("dnsy_session={}; dnsy_csrf={}", s.id, s.csrf));
            }
            Auth::SessionWrongCsrf(s) => {
                cookies.push(format!("dnsy_session={}; dnsy_csrf={}", s.id, s.csrf));
                b = b.header("x-csrf-token", format!("{}x", s.csrf));
            }
            Auth::SessionCookieOnly(s) => cookies.push(format!("dnsy_session={}", s.id)),
        }
        if !cookies.is_empty() {
            b = b.header("cookie", cookies.join("; "));
        }
        for (k, v) in self.headers {
            b = b.header(
                HeaderName::from_bytes(k.as_bytes()).expect("header name"),
                HeaderValue::from_str(&v).expect("header value"),
            );
        }
        if let Some((bytes, ct)) = self.body {
            b = b.header("content-type", ct).body(bytes);
        }
        b
    }

    pub async fn send(self) -> Resp {
        let resp = self.build().send().await.expect("API request");
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let text = resp.text().await.expect("API body");
        Resp {
            status,
            headers,
            text,
        }
    }

    /// Sends the request and returns the response before its body ends (for event streams).
    pub async fn stream(self) -> Stream {
        let resp = self.build().send().await.expect("API request");
        Stream {
            status: resp.status().as_u16(),
            headers: resp.headers().clone(),
            resp,
            buf: String::new(),
        }
    }
}

/// An open `text/event-stream`.
pub struct Stream {
    pub status: u16,
    pub headers: HeaderMap,
    resp: reqwest::Response,
    buf: String,
}

impl Stream {
    /// The next `(event, data)` pair, panicking after `deadline`.
    pub async fn next_event(&mut self, deadline: Duration) -> (String, String) {
        let end = Instant::now() + deadline;
        loop {
            if let Some(at) = self.buf.find("\n\n") {
                let block: String = self.buf.drain(..at + 2).collect();
                let mut event = String::from("message");
                let mut data = Vec::new();
                for line in block.lines() {
                    if let Some(v) = line.strip_prefix("event:") {
                        v.trim().clone_into(&mut event);
                    } else if let Some(v) = line.strip_prefix("data:") {
                        data.push(v.trim_start().to_owned());
                    }
                }
                if data.is_empty() {
                    continue; // a comment or keep-alive
                }
                return (event, data.join("\n"));
            }
            let left = end
                .checked_duration_since(Instant::now())
                .expect("timed out waiting for an event");
            let chunk = tokio::time::timeout(left, self.resp.chunk())
                .await
                .expect("timed out waiting for an event")
                .expect("read event stream")
                .expect("event stream ended");
            self.buf
                .push_str(&String::from_utf8_lossy(&chunk).replace("\r\n", "\n"));
        }
    }
}

/// Entry point: requests against one server's API.
pub struct Api {
    base: String,
    http: reqwest::Client,
}

impl Api {
    pub fn new(addr: std::net::SocketAddr) -> Api {
        Api {
            base: format!("http://{addr}"),
            http: reqwest::Client::builder()
                .timeout(DEADLINE)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("http client"),
        }
    }

    /// Like [`Api::new`] but connecting from the loopback source address `source`, to exercise
    /// per-client behaviour.
    pub fn from_source(addr: std::net::SocketAddr, source: std::net::IpAddr) -> Api {
        Api {
            base: format!("http://{addr}"),
            http: reqwest::Client::builder()
                .timeout(DEADLINE)
                .redirect(reqwest::redirect::Policy::none())
                .local_address(source)
                .build()
                .expect("http client"),
        }
    }

    /// A request to `/api/v1` + `path`.
    pub fn req(&self, method: Method, path: &str) -> Req<'_> {
        self.raw(method, &format!("/api/v1{path}"))
    }

    /// A request to an absolute path such as `/healthz`.
    pub fn raw(&self, method: Method, path: &str) -> Req<'_> {
        Req {
            api: self,
            method,
            url: format!("{}{path}", self.base),
            auth: Auth::None,
            body: None,
            headers: Vec::new(),
        }
    }

    pub async fn get(&self, path: &str, auth: Auth<'_>) -> Resp {
        self.req(Method::GET, path).auth(auth).send().await
    }

    pub async fn post(&self, path: &str, auth: Auth<'_>, body: &Value) -> Resp {
        self.req(Method::POST, path)
            .auth(auth)
            .json(body)
            .send()
            .await
    }

    pub async fn put(&self, path: &str, auth: Auth<'_>, body: &Value) -> Resp {
        self.req(Method::PUT, path)
            .auth(auth)
            .json(body)
            .send()
            .await
    }

    pub async fn patch(&self, path: &str, auth: Auth<'_>, body: &Value) -> Resp {
        self.req(Method::PATCH, path)
            .auth(auth)
            .json(body)
            .send()
            .await
    }

    pub async fn delete(&self, path: &str, auth: Auth<'_>) -> Resp {
        self.req(Method::DELETE, path).auth(auth).send().await
    }

    /// `POST /auth/login`; the response carries the cookies on success.
    pub async fn login_resp(&self, username: &str, password: &str) -> Resp {
        self.post(
            "/auth/login",
            Auth::None,
            &json!({"username": username, "password": password}),
        )
        .await
    }

    /// Logs in and returns the session.
    pub async fn login(&self, username: &str, password: &str) -> Session {
        let r = self.login_resp(username, password).await;
        assert_eq!(r.status, 200, "login of {username}: {}", r.text);
        session_of(&r)
    }

    /// Creates a user with the admin `token`; returns its id.
    pub async fn create_user(
        &self,
        token: &str,
        username: &str,
        password: &str,
        role: &str,
    ) -> i64 {
        let r = self
            .post(
                "/users",
                Auth::Bearer(token),
                &json!({"username": username, "password": password, "role": role}),
            )
            .await;
        r.ok(201)["id"].as_i64().expect("user id")
    }

    /// Creates a user with `role`, logs in and mints a token with `scopes` for it.
    pub async fn token_for(
        &self,
        admin_token: &str,
        username: &str,
        role: &str,
        scopes: &[&str],
    ) -> String {
        let password = format!("{username}-password-1234");
        self.create_user(admin_token, username, &password, role)
            .await;
        let session = self.login(username, &password).await;
        let r = self
            .post(
                "/tokens",
                Auth::Session(&session),
                &json!({"name": format!("{username}-token"), "scopes": scopes}),
            )
            .await;
        r.ok(201)["token"].as_str().expect("token").to_owned()
    }
}

/// The session cookies of a login response.
pub fn session_of(r: &Resp) -> Session {
    Session {
        id: r.cookie_value("dnsy_session").expect("session cookie"),
        csrf: r.cookie_value("dnsy_csrf").expect("csrf cookie"),
    }
}

impl Harness {
    /// A client for this server's REST API.
    pub fn rest(&self) -> Api {
        Api::new(self.api)
    }

    /// A REST client whose connections come from the loopback address `source`.
    pub fn rest_from(&self, source: &str) -> Api {
        Api::from_source(self.api, source.parse().expect("source address"))
    }
}
