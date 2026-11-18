use std::sync::Arc;

use crate::fixtures::{HarHeader, Recorder, Replayer};
use crate::rules::{CspOverride, RedirectRule, local_target_host};
use crate::status::{Decision, EventLog, now_ms};
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{HeaderMap, Request, Response, body::Bytes, header},
};

/// Replace or remove every `Content-Security-Policy` header.
///
/// `HeaderMap::insert` replaces all values previously stored under the key, so
/// a single insert collapses multiple CSP headers into one.
/// `Content-Security-Policy-Report-Only` is a different header name and is
/// never touched.
fn apply_csp_override(headers: &mut HeaderMap, csp: &CspOverride) {
    match csp {
        CspOverride::Off => {
            headers.remove(header::CONTENT_SECURITY_POLICY);
        }
        CspOverride::Policy(policy) => {
            if let Ok(value) = header::HeaderValue::from_str(policy) {
                headers.insert(header::CONTENT_SECURITY_POLICY, value);
            }
            // Policy was validated at CLI parse time, so from_str cannot fail
            // here; if it somehow does, leave the headers untouched.
        }
    }
}

/// The original prod URL of a request, as seen before any rewrite: absolute
/// URIs (plain-HTTP proxy requests) keep their scheme; requests on decrypted
/// TLS connections without a scheme in the URI are composed as `https://`.
/// Both recording and replaying use this, so the keys always match.
fn original_url(req: &Request<Body>) -> String {
    let uri = req.uri();

    if uri.scheme_str().is_some() && uri.host().is_some() {
        return uri.to_string();
    }

    let host = DevRedirect::request_host(req).unwrap_or_default();
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    format!("https://{host}{path_and_query}")
}

fn headers_to_har(headers: &HeaderMap) -> Vec<HarHeader> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let value = value.to_str().ok()?;
            Some(HarHeader {
                name: name.as_str().to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

/// Remove the headers that stop a page from being embedded in an iframe of a
/// parent shell. Used when the matched rule sets `embed = true`; only
/// responses served from that rule's target are affected — passthrough
/// traffic keeps its headers. CSP handling is separate (`csp_override`), so
/// the typical iframe scenario is `embed = true` plus `csp_override = "off"`.
fn strip_embed_blockers(headers: &mut HeaderMap) {
    // hyper's `header` module has no constants for the cross-origin policies.
    let blockers = [
        header::X_FRAME_OPTIONS,
        header::HeaderName::from_static("cross-origin-opener-policy"),
        header::HeaderName::from_static("cross-origin-embedder-policy"),
        header::HeaderName::from_static("cross-origin-resource-policy"),
    ];

    for name in blockers {
        if headers.remove(&name).is_some() {
            tracing::debug!(%name, "removed embed blocker from target response");
        }
    }
}

/// Remove the headers that describe a body when the actual body could not be
/// delivered: on a buffering failure the client gets an empty body, and stale
/// `Content-Length`/`Content-Encoding`/`Transfer-Encoding` would make it wait
/// for (or misdecode) bytes that never arrive.
fn strip_stale_body_headers(headers: &mut HeaderMap) {
    for name in [
        header::CONTENT_LENGTH,
        header::CONTENT_ENCODING,
        header::TRANSFER_ENCODING,
    ] {
        headers.remove(name);
    }
}

/// What to do to the response of the current request: CSP override from the
/// matched rule plus whether the rule asked to shed embedding blockers.
#[derive(Clone, Debug, Default)]
struct ResponseEdits {
    csp_override: Option<CspOverride>,
    embed: bool,
}

impl ResponseEdits {
    fn from_rule(rule: &RedirectRule) -> Self {
        Self {
            csp_override: rule.csp_override().cloned(),
            embed: rule.embed(),
        }
    }
}

/// Per-request correlation: the status event id, start time and response
/// edits of the most recent matched request, consumed by `handle_response`
/// of the same request.
///
/// hudsucker clones the handler per request, so this must NOT be an
/// accumulating structure: a queue would leak entries from the CONNECT
/// phase into every clone (clones are made from the instance that already
/// processed CONNECT). Overwriting the field in `handle_request` makes
/// inherited values irrelevant.
#[derive(Clone, Debug)]
struct Pending {
    event_id: u64,
    started_ms: u64,
    edits: ResponseEdits,
}

/// Per-request metadata for the recording phase: the request method, the
/// original prod URL and request headers, captured before any rewrite.
#[derive(Clone, Debug)]
struct RecordMeta {
    method: String,
    url: String,
    headers: Vec<HarHeader>,
    started_ms: u128,
}

#[derive(Clone, Debug)]
pub struct DevRedirect {
    /// Current rule set, shared with the hot-reload watcher: the watcher
    /// swaps the contents while running handler clones keep reading.
    rules: std::sync::Arc<std::sync::RwLock<Vec<RedirectRule>>>,
    /// Shared status event log: the status page server reads what we record.
    events: Arc<EventLog>,
    /// `--record <dir>`: write intercepted exchanges into a HAR file.
    recorder: Option<Arc<Recorder>>,
    /// `--replay <file>`: answer requests from a recorded session before the
    /// rules get a chance.
    replayer: Option<Arc<Replayer>>,
    pending: Option<Pending>,
    pending_record: Option<RecordMeta>,
}

impl DevRedirect {
    pub fn new(rules: Vec<RedirectRule>) -> Self {
        Self::with_events(rules, EventLog::new())
    }

    pub fn with_events(rules: Vec<RedirectRule>, events: Arc<EventLog>) -> Self {
        Self {
            rules: std::sync::Arc::new(std::sync::RwLock::new(rules)),
            events,
            recorder: None,
            replayer: None,
            pending: None,
            pending_record: None,
        }
    }

    pub fn with_fixtures(
        rules: Vec<RedirectRule>,
        recorder: Option<Arc<Recorder>>,
        replayer: Option<Arc<Replayer>>,
    ) -> Self {
        Self {
            rules: std::sync::Arc::new(std::sync::RwLock::new(rules)),
            events: EventLog::new(),
            recorder,
            replayer,
            pending: None,
            pending_record: None,
        }
    }

    pub fn rules_handle(&self) -> std::sync::Arc<std::sync::RwLock<Vec<RedirectRule>>> {
        std::sync::Arc::clone(&self.rules)
    }

    /// The shared event log handle for the status page server.
    pub fn events_handle(&self) -> Arc<EventLog> {
        Arc::clone(&self.events)
    }

    /// Replay from fixtures has priority over the rules: an offline smoke
    /// must not touch the network. The original prod URL is the key.
    fn replay_response(&self, req: &Request<Body>) -> Option<Response<Body>> {
        use base64::Engine;

        let replayer = self.replayer.as_ref()?;
        let url = original_url(req);

        let recorded = replayer.lookup(req.method().as_str(), &url)?;

        let mut builder = Response::builder().status(recorded.status);
        for header in &recorded.headers {
            if let (Ok(name), Ok(value)) = (
                header.name.parse::<header::HeaderName>(),
                header::HeaderValue::from_str(&header.value),
            ) {
                builder = builder.header(name, value);
            }
        }

        let text = recorded.content.text.as_deref().unwrap_or_default();
        let body = if recorded.content.encoding.as_deref() == Some("base64") {
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .unwrap_or_default()
        } else {
            text.as_bytes().to_vec()
        };

        tracing::info!(%url, status = recorded.status, "replaying response from fixtures");

        Some(
            builder
                .body(Body::from(body))
                .expect("fixture response with valid status builds"),
        )
    }

    fn record_meta(req: &Request<Body>) -> Option<RecordMeta> {
        Some(RecordMeta {
            method: req.method().to_string(),
            url: original_url(req),
            headers: headers_to_har(req.headers()),
            started_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
        })
    }

    /// Host of an intercepted request: the `host` header, falling back to the
    /// URI host — HTTP/2 requests carry the authority in `:authority`, not a
    /// `host` header, so without the fallback they would never match.
    fn request_host(req: &Request<Body>) -> Option<String> {
        req.headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .or_else(|| req.uri().host().map(str::to_string))
    }

    /// Snapshot of the current rules for startup logging.
    pub fn rules(&self) -> Vec<RedirectRule> {
        self.rules.read().expect("rules lock is poisoned").clone()
    }

    /// Index (first-match-wins) and a snapshot of the rule matching the
    /// request. `intercept = false` rules never rewrite traffic: their host
    /// is tunneled untouched, so a matching request must not be redirected
    /// (plain-HTTP requests reach the handler without a TLS layer).
    fn matching_rule_index(&self, req: &Request<Body>) -> Option<(usize, RedirectRule)> {
        let host = Self::request_host(req)?;
        let path = req.uri().path();

        let rules = self.rules.read().expect("rules lock is poisoned");

        rules
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.intercept() && rule.matches(&host, path))
            .map(|(index, rule)| (index, rule.clone()))
    }

    /// Whether the host has any rule at all (for miss-reason wording).
    fn matches_any_host(&self, host: &str) -> bool {
        self.rules
            .read()
            .expect("rules lock is poisoned")
            .iter()
            .any(|rule| rule.matches_host(host))
    }

    /// Whether the host has an interceptable rule.
    fn has_interceptable_host(&self, host: &str) -> bool {
        self.rules
            .read()
            .expect("rules lock is poisoned")
            .iter()
            .any(|rule| rule.intercept() && rule.matches_host(host))
    }

    /// TLS interception decision for an SNI host: decrypt only when some rule
    /// for the host asks to intercept. With no such rule the CONNECT is
    /// tunneled as-is and only a CONNECT line shows up in the logs.
    fn should_intercept(&self, server_name: &str) -> bool {
        self.rules
            .read()
            .expect("rules lock is poisoned")
            .iter()
            .any(|rule| rule.intercept() && rule.matches_host(server_name))
    }
}

impl HttpHandler for DevRedirect {
    async fn should_intercept_tls(
        &mut self,
        _ctx: &HttpContext,
        client_hello: hudsucker::rustls::server::ClientHello<'_>,
    ) -> bool {
        let Some(server_name) = client_hello.server_name() else {
            self.events.record_connect(
                "",
                Decision::Missed {
                    reason: "no SNI in ClientHello".into(),
                },
            );
            return false;
        };

        let intercept = self.should_intercept(server_name);

        if intercept {
            self.events.record_connect(
                server_name,
                Decision::Matched {
                    rule_index: 0,
                    target: "(TLS decrypted)".into(),
                },
            );
        } else if self.matches_any_host(server_name) {
            tracing::info!(
                host = %server_name,
                "TLS passthrough: rule sets intercept = false"
            );
            self.events.record_connect(server_name, Decision::Tunnel);
        } else {
            self.events.record_connect(
                server_name,
                Decision::Missed {
                    reason: "host not configured".into(),
                },
            );
        }

        intercept
    }

    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        self.handle_request_inner(req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        self.handle_response_inner(res).await
    }
}

impl DevRedirect {
    fn handle_request_inner(&mut self, mut req: Request<Body>) -> RequestOrResponse {
        if let Some(response) = self.replay_response(&req) {
            return RequestOrResponse::Response(response);
        }

        self.pending_record = self.recorder.as_ref().and_then(|_| Self::record_meta(&req));

        let matched = self.matching_rule_index(&req);

        tracing::info!(
            method = %req.method(),
            host = ?req.headers().get(header::HOST),
            uri = %req.uri(),
            matches = matched.is_some(),
            "HTTP request"
        );

        let host = Self::request_host(&req).unwrap_or_default();
        let path = req.uri().path().to_string();
        let method = req.method().to_string();
        let started_ms = now_ms();

        let Some((rule_index, rule)) = matched else {
            let reason = if self.has_interceptable_host(&host) {
                "no rule matched the path"
            } else if self.matches_any_host(&host) {
                "host is TLS passthrough (intercept = false)"
            } else {
                "host not configured"
            };

            let event_id = self.events.record_request(
                &method,
                &host,
                &path,
                Decision::Missed {
                    reason: reason.into(),
                },
            );
            self.pending = Some(Pending {
                event_id,
                started_ms,
                edits: ResponseEdits::default(),
            });
            // Missed requests go to prod unchanged; recording covers
            // intercepted hosts' traffic regardless, keep the meta.

            return RequestOrResponse::Request(req);
        };

        let event_id = self.events.record_request(
            &method,
            &host,
            &path,
            Decision::Matched {
                rule_index,
                target: rule.target().to_string(),
            },
        );

        // Map Local: a `file:` target serves static files directly instead of
        // redirecting to a dev server. The response is built here, so its
        // response edits, outcome and HAR entry are recorded here too —
        // `handle_response` never sees it.
        if rule.is_file_target() {
            let (mut res, file_body) = serve_from_file_target(&rule, &req);
            let edits = ResponseEdits::from_rule(&rule);

            if let Some(csp_override) = &edits.csp_override {
                apply_csp_override(res.headers_mut(), csp_override);
                tracing::info!(
                    ?csp_override,
                    "csp override applied to file-target response"
                );
            }

            if edits.embed {
                strip_embed_blockers(res.headers_mut());
            }

            self.events.record_response(
                event_id,
                res.status().as_u16(),
                now_ms().saturating_sub(started_ms),
            );

            // File-target answers must land in the HAR too, or a replay of
            // the session would lose every Map Local response. A HEAD answer
            // records an empty body — the client never received one either.
            if let Some(recorder) = self.recorder.as_ref() {
                recorder.record(
                    &method,
                    &original_url(&req),
                    headers_to_har(req.headers()),
                    res.status().as_u16(),
                    headers_to_har(res.headers()),
                    &file_body,
                    now_ms().saturating_sub(started_ms) as i64,
                );
            }

            return RequestOrResponse::Response(res);
        }

        let edits = self.rewrite_request(&rule, &mut req);

        self.pending = Some(Pending {
            event_id,
            started_ms,
            edits,
        });

        RequestOrResponse::Request(req)
    }

    fn rewrite_request(&self, rule: &RedirectRule, req: &mut Request<Body>) -> ResponseEdits {
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .to_string();

        let Some(new_uri) = rule.target_uri(&path_and_query) else {
            tracing::error!(
                uri = ?req.uri(),
                "failed to construct local target URI"
            );

            return ResponseEdits::default();
        };

        *req.uri_mut() = new_uri;

        let host_value = match local_target_host(rule.target()) {
            Some(host) => host,
            None => {
                tracing::error!(
                    target = %rule.target(),
                    "failed to extract local target host"
                );

                return ResponseEdits::default();
            }
        };

        if let Ok(value) = host_value.parse() {
            req.headers_mut().insert(header::HOST, value);
        }

        tracing::info!(
            host = %rule.host(),
            path = %path_and_query,
            target = %rule.target(),
            "redirecting request to local dev server"
        );

        ResponseEdits::from_rule(rule)
    }

    async fn handle_response_inner(&mut self, mut res: Response<Body>) -> Response<Body> {
        if let Some(pending) = self.pending.take() {
            if let Some(csp_override) = &pending.edits.csp_override {
                apply_csp_override(res.headers_mut(), csp_override);

                tracing::info!(?csp_override, "csp override applied to redirected response");
            }

            if pending.edits.embed {
                strip_embed_blockers(res.headers_mut());
            }

            self.events.record_response(
                pending.event_id,
                res.status().as_u16(),
                now_ms().saturating_sub(pending.started_ms),
            );
        }

        // Recording needs the whole body, which means buffering: streaming
        // responses (SSE, long-poll) are not suitable for recording anyway.
        if let (Some(meta), Some(recorder)) = (self.pending_record.take(), self.recorder.clone()) {
            return self.buffer_and_record(recorder, meta, res).await;
        }

        res
    }

    async fn buffer_and_record(
        &self,
        recorder: Arc<Recorder>,
        meta: RecordMeta,
        res: Response<Body>,
    ) -> Response<Body> {
        use http_body_util::BodyExt;

        let (mut parts, body) = res.into_parts();
        let bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                tracing::warn!(%err, url = %meta.url, "failed to buffer response for recording");
                // The client gets an empty body now; the stale length and
                // encoding headers would describe bytes that never arrive.
                strip_stale_body_headers(&mut parts.headers);
                return Response::from_parts(parts, Body::empty());
            }
        };

        recorder.record(
            &meta.method,
            &meta.url,
            meta.headers,
            parts.status.as_u16(),
            headers_to_har(&parts.headers),
            &bytes,
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0)
                - meta.started_ms as i64)
                .max(0),
        );

        // `Bytes` is cheap to clone — no need to copy into a Vec.
        Response::from_parts(parts, Body::from(bytes))
    }
}

/// Content-Type by file extension for Map Local responses. Text types carry
/// a charset; unknown extensions are served as `application/octet-stream`.
fn mime_type(path: &std::path::Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        _ => "application/octet-stream",
    }
}

/// Decode `%XX` sequences of a URL path. `None` on malformed escapes or
/// non-UTF-8 output.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hi = (hex[0] as char).to_digit(16)?;
            let lo = (hex[1] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8(out).ok()
}

/// Static text response plus the exact bytes it carries, so the exchange can
/// be recorded into the HAR without re-buffering the body.
fn plain_response(status: hudsucker::hyper::StatusCode, body: &str) -> (Response<Body>, Bytes) {
    let bytes = Bytes::from(body.to_owned());
    let res = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, body.len())
        .body(Body::from(bytes.clone()))
        .expect("static response with fixed parts always builds");

    (res, bytes)
}

/// Map Local: serve a request from the `file:<dir>` target's directory by the
/// requested path — the cheap way to put local assets on top of prod without
/// a dev server. `..` segments and symlink escapes are rejected; directories
/// are not listed; the query string is not part of the lookup.
///
/// Returns the response and the exact body bytes it carries (empty for HEAD
/// and error answers), so the caller can record the exchange into the HAR.
fn serve_from_file_target(rule: &RedirectRule, req: &Request<Body>) -> (Response<Body>, Bytes) {
    use hudsucker::hyper::{Method, StatusCode};
    use std::path::PathBuf;

    let dir = rule.file_dir().expect("file target checked by caller");
    let head = req.method() == Method::HEAD;

    if req.method() != Method::GET && !head {
        return plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "only GET and HEAD are served\n",
        );
    }

    let Some(url_path) = percent_decode(req.uri().path()) else {
        return plain_response(StatusCode::BAD_REQUEST, "malformed path encoding\n");
    };

    let mut path = PathBuf::from(dir);
    for segment in url_path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                tracing::warn!(path = %url_path, "rejected path traversal in file target");
                return plain_response(StatusCode::FORBIDDEN, "path traversal rejected\n");
            }
            segment => path.push(segment),
        }
    }

    let Ok(canonical_dir) = std::fs::canonicalize(dir) else {
        tracing::error!(dir, "file target directory does not exist");
        return plain_response(StatusCode::NOT_FOUND, "not found\n");
    };

    let Ok(canonical) = std::fs::canonicalize(&path) else {
        return plain_response(StatusCode::NOT_FOUND, "not found\n");
    };

    if !canonical.starts_with(&canonical_dir) {
        tracing::warn!(path = %url_path, "resolved outside the file target directory");
        return plain_response(StatusCode::FORBIDDEN, "path traversal rejected\n");
    }

    if canonical.is_dir() {
        return plain_response(StatusCode::NOT_FOUND, "not found\n");
    }

    let Ok(bytes) = std::fs::read(&canonical) else {
        return plain_response(StatusCode::NOT_FOUND, "not found\n");
    };

    tracing::info!(
        path = %url_path,
        bytes = bytes.len(),
        "serving file from file target"
    );

    let bytes = Bytes::from(bytes);
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime_type(&canonical))
        .header(header::CONTENT_LENGTH, bytes.len());

    let recorded = if head { Bytes::new() } else { bytes.clone() };
    let res = if head {
        builder.body(Body::empty())
    } else {
        builder.body(Body::from(bytes))
    }
    .expect("static response with fixed parts always builds");

    (res, recorded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_csp(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(header::CONTENT_SECURITY_POLICY, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn policy_replaces_existing_csp() {
        let mut headers = headers_with_csp(&["frame-ancestors 'self'"]);
        apply_csp_override(
            &mut headers,
            &CspOverride::Policy("frame-ancestors *".into()),
        );

        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors *"
        );
    }

    #[test]
    fn off_removes_all_csp_headers() {
        let mut headers = headers_with_csp(&["default-src 'self'", "frame-ancestors 'none'"]);
        apply_csp_override(&mut headers, &CspOverride::Off);

        assert!(!headers.contains_key(header::CONTENT_SECURITY_POLICY));
    }

    #[test]
    fn policy_collapses_multiple_csp_headers_into_one() {
        let mut headers = headers_with_csp(&["default-src 'self'", "frame-ancestors 'self'"]);
        apply_csp_override(
            &mut headers,
            &CspOverride::Policy("frame-ancestors *".into()),
        );

        assert_eq!(
            headers
                .get_all(header::CONTENT_SECURITY_POLICY)
                .iter()
                .count(),
            1
        );
    }

    #[test]
    fn report_only_is_untouched() {
        let mut headers = headers_with_csp(&["frame-ancestors 'self'"]);
        headers.append(
            header::CONTENT_SECURITY_POLICY_REPORT_ONLY,
            "default-src 'none'".parse().unwrap(),
        );

        apply_csp_override(&mut headers, &CspOverride::Off);

        assert!(!headers.contains_key(header::CONTENT_SECURITY_POLICY));
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY_REPORT_ONLY],
            "default-src 'none'"
        );
    }

    fn handler(csp_override: Option<CspOverride>) -> DevRedirect {
        DevRedirect::new(vec![RedirectRule::new(
            "example.com".into(),
            "/".into(),
            "http://127.0.0.1:5173".into(),
            csp_override,
            true,
            false,
        )])
    }

    fn embed_handler() -> DevRedirect {
        DevRedirect::new(vec![RedirectRule::new(
            "example.com".into(),
            "/".into(),
            "http://127.0.0.1:5173".into(),
            None,
            true,
            true,
        )])
    }

    fn request_to(host: &str, path: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("https://{host}{path}"))
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap()
    }

    fn response_with_csp(policy: &str) -> Response<Body> {
        let mut res = Response::new(Body::empty());
        res.headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, policy.parse().unwrap());
        res
    }

    #[test]
    fn rule_matches_http2_request_without_host_header() {
        // HTTP/2 carries the authority in the URI (`:authority`), not a `host`
        // header — matching must fall back to the URI host, or such requests
        // silently bypass the redirect.
        let rule = RedirectRule::new(
            "example.com".into(),
            "/".into(),
            "http://127.0.0.1:5173".into(),
            None,
            true,
            false,
        );
        let req = Request::builder()
            .uri("https://example.com/app.js")
            .body(Body::empty())
            .unwrap();

        let host = DevRedirect::request_host(&req).unwrap();

        assert!(rule.matches(&host, req.uri().path()));
    }

    #[tokio::test]
    async fn response_for_redirected_request_gets_override() {
        let mut h = handler(Some(CspOverride::Off));

        let req = request_to("example.com", "/app.js");
        let _ = h.handle_request_inner(req);

        let res = h
            .handle_response_inner(response_with_csp("frame-ancestors 'self'"))
            .await;

        assert!(!res.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    }

    #[tokio::test]
    async fn response_for_passthrough_request_is_untouched() {
        let mut h = handler(Some(CspOverride::Off));

        let req = request_to("other.com", "/app.js");
        let _ = h.handle_request_inner(req);

        let res = h
            .handle_response_inner(response_with_csp("frame-ancestors 'self'"))
            .await;

        assert_eq!(
            res.headers()[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'self'"
        );
    }

    #[tokio::test]
    async fn response_without_override_keeps_csp() {
        let mut h = handler(None);

        let req = request_to("example.com", "/app.js");
        let _ = h.handle_request_inner(req);

        let res = h
            .handle_response_inner(response_with_csp("frame-ancestors 'self'"))
            .await;

        assert_eq!(
            res.headers()[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'self'"
        );
    }

    #[tokio::test]
    async fn response_without_prior_request_is_untouched() {
        let mut h = handler(Some(CspOverride::Off));

        let res = h
            .handle_response_inner(response_with_csp("frame-ancestors 'self'"))
            .await;

        assert_eq!(
            res.headers()[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'self'"
        );
    }

    // ---- per-rule TLS passthrough (intercept = false) ----

    // ---- embed: shed iframe blockers on target responses ----

    #[tokio::test]
    async fn embed_sheds_all_blockers_on_target_response() {
        let mut h = embed_handler();

        let req = request_to("example.com", "/app.js");
        let _ = h.handle_request_inner(req);

        let mut res = Response::new(Body::empty());
        for (name, value) in [
            (header::X_FRAME_OPTIONS, "DENY"),
            (
                header::HeaderName::from_static("cross-origin-opener-policy"),
                "same-origin",
            ),
            (
                header::HeaderName::from_static("cross-origin-embedder-policy"),
                "require-corp",
            ),
            (
                header::HeaderName::from_static("cross-origin-resource-policy"),
                "same-origin",
            ),
        ] {
            res.headers_mut()
                .insert(name, header::HeaderValue::from_static(value));
        }
        res.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'".parse().unwrap(),
        );

        let res = h.handle_response_inner(res).await;

        assert!(!res.headers().contains_key(header::X_FRAME_OPTIONS));
        assert!(!res.headers().contains_key("cross-origin-opener-policy"));
        assert!(!res.headers().contains_key("cross-origin-embedder-policy"));
        assert!(!res.headers().contains_key("cross-origin-resource-policy"));
        // CSP is a separate concern: without csp_override it survives.
        assert!(res.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    }

    #[tokio::test]
    async fn embed_false_keeps_blockers_on_target_response() {
        let mut h = handler(None);

        let req = request_to("example.com", "/app.js");
        let _ = h.handle_request_inner(req);

        let mut res = Response::new(Body::empty());
        res.headers_mut().insert(
            header::X_FRAME_OPTIONS,
            header::HeaderValue::from_static("DENY"),
        );

        let res = h.handle_response_inner(res).await;

        assert_eq!(res.headers()[header::X_FRAME_OPTIONS], "DENY");
    }

    #[tokio::test]
    async fn embed_does_not_touch_passthrough_responses() {
        let mut h = embed_handler();

        let req = request_to("other.com", "/app.js");
        let _ = h.handle_request_inner(req);

        let mut res = Response::new(Body::empty());
        res.headers_mut().insert(
            header::X_FRAME_OPTIONS,
            header::HeaderValue::from_static("DENY"),
        );

        let res = h.handle_response_inner(res).await;

        assert_eq!(res.headers()[header::X_FRAME_OPTIONS], "DENY");
    }

    #[tokio::test]
    async fn embed_and_csp_override_apply_together() {
        // The typical iframe scenario: embed = true + csp_override = "off".
        let mut h = DevRedirect::new(vec![RedirectRule::new(
            "example.com".into(),
            "/".into(),
            "http://127.0.0.1:5173".into(),
            Some(CspOverride::Off),
            true,
            true,
        )]);

        let req = request_to("example.com", "/app.js");
        let _ = h.handle_request_inner(req);

        let mut res = Response::new(Body::empty());
        res.headers_mut().insert(
            header::X_FRAME_OPTIONS,
            header::HeaderValue::from_static("DENY"),
        );
        res.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'".parse().unwrap(),
        );

        let res = h.handle_response_inner(res).await;

        assert!(!res.headers().contains_key(header::X_FRAME_OPTIONS));
        assert!(!res.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    }

    #[test]
    fn tls_intercepted_only_when_a_rule_asks_for_it() {
        let h = DevRedirect::new(vec![RedirectRule::new(
            "example.com".into(),
            "/".into(),
            "http://127.0.0.1:5173".into(),
            None,
            true,
            false,
        )]);

        assert!(h.should_intercept("example.com"));
        assert!(!h.should_intercept("other.com"));
    }

    #[test]
    fn tls_passthrough_when_rule_sets_intercept_false() {
        let h = DevRedirect::new(vec![RedirectRule::new(
            "pinned.example.com".into(),
            "/".into(),
            "http://127.0.0.1:5173".into(),
            None,
            false,
            false,
        )]);

        assert!(!h.should_intercept("pinned.example.com"));
        // The host is still known to the PAC (routed via the proxy), it is
        // only tunneled instead of decrypted.
        assert!(h.matches_any_host("pinned.example.com"));
    }

    #[test]
    fn passthrough_rule_never_rewrites_requests() {
        let mut h = DevRedirect::new(vec![RedirectRule::new(
            "pinned.example.com".into(),
            "/".into(),
            "http://127.0.0.1:5173".into(),
            None,
            false,
            false,
        )]);

        // Plain-HTTP requests to the host reach the handler without a TLS
        // layer; they must pass through untouched as well.
        let RequestOrResponse::Request(req) =
            h.handle_request_inner(request_to("pinned.example.com", "/app.js"))
        else {
            panic!("passthrough rules must pass requests through untouched");
        };
        assert_eq!(req.uri().to_string(), "https://pinned.example.com/app.js");
        assert_eq!(req.headers()[header::HOST], "pinned.example.com");
    }

    #[test]
    fn one_interceptable_rule_is_enough_to_decrypt_the_host() {
        let h = DevRedirect::new(vec![
            RedirectRule::new(
                "example.com".into(),
                "/api/".into(),
                "http://127.0.0.1:1111".into(),
                None,
                false,
                false,
            ),
            RedirectRule::new(
                "example.com".into(),
                "/".into(),
                "http://127.0.0.1:2222".into(),
                None,
                true,
                false,
            ),
        ]);

        assert!(h.should_intercept("example.com"));
    }

    #[tokio::test]
    async fn non_redirected_state_does_not_leak_into_cloned_handler() {
        // Real hudsucker flow: one handler instance processes the CONNECT
        // request (no redirect), then `serve_stream` clones that instance for
        // every decrypted inner request. The clone must not inherit the
        // non-redirected outcome: its own request decides.
        let mut connect_handler = handler(Some(CspOverride::Off));
        let _ = connect_handler.handle_request_inner(request_to("other.com", "/"));

        let mut inner = connect_handler.clone();
        let _ = inner.handle_request_inner(request_to("example.com", "/"));

        let res = inner
            .handle_response_inner(response_with_csp("frame-ancestors 'self'"))
            .await;

        assert!(!res.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    }

    fn multi_rule_handler() -> DevRedirect {
        DevRedirect::new(vec![
            RedirectRule::new(
                "example.com".into(),
                "/app/".into(),
                "http://127.0.0.1:1111".into(),
                Some(CspOverride::Policy("policy-a".into())),
                true,
                false,
            ),
            RedirectRule::new(
                "example.com".into(),
                "/".into(),
                "http://127.0.0.1:2222".into(),
                Some(CspOverride::Policy("policy-b".into())),
                true,
                false,
            ),
            RedirectRule::new(
                "other.com".into(),
                "/".into(),
                "http://127.0.0.1:3333".into(),
                Some(CspOverride::Off),
                true,
                false,
            ),
        ])
    }

    #[tokio::test]
    async fn first_matching_rule_wins() {
        let mut h = multi_rule_handler();

        let RequestOrResponse::Request(req) =
            h.handle_request_inner(request_to("example.com", "/app/main.js"))
        else {
            panic!("redirect rules must pass the request through");
        };
        assert_eq!(req.uri().to_string(), "http://127.0.0.1:1111/app/main.js");

        let res = h
            .handle_response_inner(response_with_csp("frame-ancestors 'self'"))
            .await;

        assert_eq!(res.headers()[header::CONTENT_SECURITY_POLICY], "policy-a");
    }

    #[test]
    fn redirect_uses_matched_rule_target() {
        let mut h = multi_rule_handler();

        let RequestOrResponse::Request(req) =
            h.handle_request_inner(request_to("example.com", "/other.js"))
        else {
            panic!("redirect rules must pass the request through");
        };
        assert_eq!(req.uri().to_string(), "http://127.0.0.1:2222/other.js");
    }

    #[tokio::test]
    async fn per_rule_csp_isolated() {
        let mut h = DevRedirect::new(vec![
            RedirectRule::new(
                "plain.com".into(),
                "/".into(),
                "http://127.0.0.1:1111".into(),
                None,
                true,
                false,
            ),
            RedirectRule::new(
                "stripped.com".into(),
                "/".into(),
                "http://127.0.0.1:2222".into(),
                Some(CspOverride::Off),
                true,
                false,
            ),
        ]);

        let req = request_to("plain.com", "/");
        let _ = h.handle_request_inner(req);

        let res = h
            .handle_response_inner(response_with_csp("frame-ancestors 'self'"))
            .await;

        assert_eq!(
            res.headers()[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'self'"
        );
    }

    // ---- Map Local (file: targets) ----

    fn file_rule(dir: &std::path::Path) -> RedirectRule {
        RedirectRule::new(
            "assets.example.com".into(),
            "/".into(),
            format!("file:{}", dir.display()),
            None,
            true,
            false,
        )
    }

    fn file_handler(dir: &std::path::Path) -> DevRedirect {
        DevRedirect::new(vec![file_rule(dir)])
    }

    fn file_request(path: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(format!("https://assets.example.com{path}"))
            .header(header::HOST, "assets.example.com")
            .body(Body::empty())
            .unwrap()
    }

    fn as_response(outcome: RequestOrResponse) -> Response<Body> {
        let RequestOrResponse::Response(res) = outcome else {
            panic!("file targets must answer with a response, not a rewritten request");
        };
        res
    }

    #[test]
    fn file_target_serves_bytes_with_mime_type() {
        let dir = std::env::temp_dir().join(format!("rexy-maplocal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app.js"), b"console.log(1)").unwrap();
        std::fs::write(dir.join("page.html"), b"<html></html>").unwrap();

        let mut h = file_handler(&dir);

        let res = as_response(h.handle_request_inner(file_request("/app.js?v=3")));
        assert_eq!(res.status(), 200);
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert_eq!(res.headers()[header::CONTENT_LENGTH], "14");

        let res = as_response(h.handle_request_inner(file_request("/page.html")));
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_target_missing_file_is_404() {
        let dir = std::env::temp_dir().join(format!("rexy-maplocal-404-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut h = file_handler(&dir);

        let res = as_response(h.handle_request_inner(file_request("/nope.js")));
        assert_eq!(res.status(), 404);

        // Directories are not listed, including the root.
        let res = as_response(h.handle_request_inner(file_request("/")));
        assert_eq!(res.status(), 404);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_target_rejects_traversal() {
        let dir = std::env::temp_dir().join(format!("rexy-maplocal-trav-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ok.txt"), b"ok").unwrap();

        let mut h = file_handler(&dir);

        // Literal .. and percent-encoded .. both must be rejected.
        for path in [
            "/../secret.txt",
            "/a/../../secret.txt",
            "/%2e%2e/secret.txt",
        ] {
            let res = as_response(h.handle_request_inner(file_request(path)));
            assert_eq!(res.status(), 403, "path {path} must be rejected");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_target_decodes_percent_escapes() {
        let dir = std::env::temp_dir().join(format!("rexy-maplocal-esc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("my file.txt"), b"hello").unwrap();

        let mut h = file_handler(&dir);

        let res = as_response(h.handle_request_inner(file_request("/my%20file.txt")));
        assert_eq!(res.status(), 200);
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_target_head_returns_headers_without_body() {
        let dir = std::env::temp_dir().join(format!("rexy-maplocal-head-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app.js"), b"console.log(1)").unwrap();

        let mut h = file_handler(&dir);

        let req = Request::builder()
            .method("HEAD")
            .uri("https://assets.example.com/app.js")
            .header(header::HOST, "assets.example.com")
            .body(Body::empty())
            .unwrap();

        let res = as_response(h.handle_request_inner(req));
        assert_eq!(res.status(), 200);
        assert_eq!(res.headers()[header::CONTENT_LENGTH], "14");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_target_post_is_method_not_allowed() {
        let dir = std::env::temp_dir().join(format!("rexy-maplocal-post-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut h = file_handler(&dir);

        let req = Request::builder()
            .method("POST")
            .uri("https://assets.example.com/app.js")
            .header(header::HOST, "assets.example.com")
            .body(Body::empty())
            .unwrap();

        let res = as_response(h.handle_request_inner(req));
        assert_eq!(res.status(), 405);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_target_applies_csp_override() {
        let dir = std::env::temp_dir().join(format!("rexy-maplocal-csp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app.js"), b"console.log(1)").unwrap();

        let mut h = DevRedirect::new(vec![RedirectRule::new(
            "assets.example.com".into(),
            "/".into(),
            format!("file:{}", dir.display()),
            Some(CspOverride::Off),
            true,
            false,
        )]);

        let res = as_response(h.handle_request_inner(file_request("/app.js")));
        assert_eq!(res.status(), 200);
        assert!(!res.headers().contains_key(header::CONTENT_SECURITY_POLICY));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn matches_any_host_across_rules() {
        let h = multi_rule_handler();

        assert!(h.matches_any_host("example.com"));
        assert!(h.matches_any_host("other.com"));
        assert!(!h.matches_any_host("third.com"));
    }

    // ---- record/replay ----

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rexy-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        dir
    }

    #[tokio::test]
    async fn recorded_exchange_keeps_request_method_and_body() {
        use http_body_util::BodyExt;

        let record_dir = temp_dir("rec-method");
        let recorder = std::sync::Arc::new(Recorder::start(&record_dir).unwrap());
        let mut h = DevRedirect::with_fixtures(
            vec![RedirectRule::new(
                "example.com".into(),
                "/".into(),
                "http://127.0.0.1:5173".into(),
                None,
                true,
                false,
            )],
            Some(std::sync::Arc::clone(&recorder)),
            None,
        );

        let req = Request::builder()
            .method("POST")
            .uri("https://example.com/api/submit")
            .header(header::HOST, "example.com")
            .body(Body::empty())
            .unwrap();
        let _ = h.handle_request_inner(req);

        let res = h
            .handle_response_inner(
                Response::builder()
                    .status(201)
                    .body(Body::from("created"))
                    .unwrap(),
            )
            .await;

        // The client still receives the full body through the recording path.
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"created");

        recorder.flush().unwrap();

        let replayer = Replayer::open(&record_dir.join("rexy-session.har")).unwrap();
        assert!(
            replayer
                .lookup("POST", "https://example.com/api/submit")
                .is_some(),
            "recorded POST must replay under POST"
        );
        assert!(
            replayer
                .lookup("GET", "https://example.com/api/submit")
                .is_none(),
            "method must not be dropped from the HAR"
        );

        std::fs::remove_dir_all(&record_dir).ok();
    }

    #[tokio::test]
    async fn buffering_failure_strips_body_describing_headers() {
        use std::pin::Pin;
        use std::task::{Context, Poll};

        // A body whose single frame is an error: emulates an upstream that
        // dies mid-response while recording is active.
        struct FailingBody;

        impl hudsucker::hyper::body::Body for FailingBody {
            type Data = hudsucker::hyper::body::Bytes;
            type Error = hudsucker::Error;

            fn poll_frame(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<hudsucker::hyper::body::Frame<Self::Data>, Self::Error>>>
            {
                Poll::Ready(Some(Err(hudsucker::Error::Unknown)))
            }
        }

        let record_dir = temp_dir("rec-fail");
        let mut h = DevRedirect::with_fixtures(
            vec![RedirectRule::new(
                "example.com".into(),
                "/".into(),
                "http://127.0.0.1:5173".into(),
                None,
                true,
                false,
            )],
            Some(std::sync::Arc::new(Recorder::start(&record_dir).unwrap())),
            None,
        );

        let _ = h.handle_request_inner(request_to("example.com", "/stream"));

        let res = Response::builder()
            .status(200)
            .header(header::CONTENT_LENGTH, "42")
            .header(header::CONTENT_ENCODING, "gzip")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(hudsucker::Body::from(
                http_body_util::combinators::BoxBody::new(FailingBody),
            ))
            .unwrap();

        let res = h.handle_response_inner(res).await;

        // The client gets an empty body: no stale length/encoding headers.
        assert!(!res.headers().contains_key(header::CONTENT_LENGTH));
        assert!(!res.headers().contains_key(header::CONTENT_ENCODING));
        assert!(!res.headers().contains_key(header::TRANSFER_ENCODING));
        // Unrelated headers survive.
        assert_eq!(res.headers()[header::CONTENT_TYPE], "text/plain");

        std::fs::remove_dir_all(&record_dir).ok();
    }

    #[tokio::test]
    async fn file_target_exchange_is_recorded_into_har() {
        let dir = temp_dir("rec-file");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app.js"), b"console.log(1)").unwrap();

        let record_dir = temp_dir("rec-file-har");
        let recorder = std::sync::Arc::new(Recorder::start(&record_dir).unwrap());
        let mut h = DevRedirect::with_fixtures(
            vec![file_rule(&dir)],
            Some(std::sync::Arc::clone(&recorder)),
            None,
        );

        let res = as_response(h.handle_request_inner(file_request("/app.js")));
        assert_eq!(res.status(), 200);

        let head_req = Request::builder()
            .method("HEAD")
            .uri("https://assets.example.com/app.js")
            .header(header::HOST, "assets.example.com")
            .body(Body::empty())
            .unwrap();
        let res = as_response(h.handle_request_inner(head_req));
        assert_eq!(res.status(), 200);

        recorder.flush().unwrap();

        let replayer = Replayer::open(&record_dir.join("rexy-session.har")).unwrap();
        // GET and HEAD are separate entries: the GET one carries the file
        // bytes, HEAD records an empty body.
        let get = replayer
            .lookup("GET", "https://assets.example.com/app.js")
            .expect("file-target GET must be recorded");
        assert_eq!(get.status, 200);
        assert_eq!(get.content.size, 14);

        let head = replayer
            .lookup("HEAD", "https://assets.example.com/app.js")
            .expect("file-target HEAD must be recorded");
        assert_eq!(head.content.size, 0);

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&record_dir).ok();
    }

    #[tokio::test]
    async fn replay_of_entry_without_content_text_returns_empty_body() {
        use http_body_util::BodyExt;

        let dir = temp_dir("replay-notext");
        std::fs::create_dir_all(&dir).unwrap();
        let har_path = dir.join("session.har");
        // Chrome DevTools export of a 304: the response content carries no
        // `text` field.
        let raw = r#"{"log":{"version":"1.2","creator":{"name":"x","version":"1"},"entries":[{"startedDateTime":"2026-01-01T00:00:00.000Z","time":0,"request":{"method":"GET","url":"https://a.example.com/x","httpVersion":"HTTP/1.1","headers":[],"queryString":[],"cookies":[],"headersSize":-1,"bodySize":-1},"response":{"status":304,"statusText":"Not Modified","httpVersion":"HTTP/1.1","headers":[],"content":{"size":0,"mimeType":"text/html"},"headersSize":-1,"bodySize":0}}]}}"#;
        std::fs::write(&har_path, raw).unwrap();

        let replayer = Replayer::open(&har_path).unwrap();
        let mut h = DevRedirect::with_fixtures(vec![], None, Some(std::sync::Arc::new(replayer)));

        let outcome = h.handle_request_inner(request_to("a.example.com", "/x"));
        let res = match outcome {
            RequestOrResponse::Response(res) => res,
            RequestOrResponse::Request(_) => panic!("replay must answer with a response"),
        };

        assert_eq!(res.status(), 304);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
