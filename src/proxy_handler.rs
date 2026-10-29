use crate::fixtures::{HarHeader, Recorder, Replayer};
use std::sync::Arc;

use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{HeaderMap, Request, Response, Uri, header},
};

/// How to rewrite the `Content-Security-Policy` header of responses served
/// from the local target. Parsed from `rexy run --csp-override`.
#[derive(Clone, Debug, PartialEq)]
pub enum CspOverride {
    /// Remove all Content-Security-Policy headers.
    Off,
    /// Replace all Content-Security-Policy headers with this policy string.
    Policy(String),
}

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

/// One redirect rule: which host/path prefix to intercept and which local
/// target to serve it from.
#[derive(Clone, Debug)]
pub struct RedirectRule {
    prod_host: String,
    path_prefix: String,
    local_target: String,
    csp_override: Option<CspOverride>,
}

impl RedirectRule {
    pub fn new(
        prod_host: String,
        path_prefix: String,
        local_target: String,
        csp_override: Option<CspOverride>,
    ) -> Self {
        Self {
            prod_host: prod_host.trim_end_matches('.').to_ascii_lowercase(),
            path_prefix: normalize_path_prefix(&path_prefix),
            local_target: local_target.trim_end_matches('/').to_string(),
            csp_override,
        }
    }

    pub fn host(&self) -> &str {
        &self.prod_host
    }

    pub fn path(&self) -> &str {
        &self.path_prefix
    }

    pub fn target(&self) -> &str {
        &self.local_target
    }

    pub fn csp_override(&self) -> Option<&CspOverride> {
        self.csp_override.as_ref()
    }

    fn matches_host(&self, host: &str) -> bool {
        normalize_host(host) == self.prod_host
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

    fn matches_request(&self, req: &Request<Body>) -> bool {
        // HTTP/2 requests carry the authority in the URI (`:authority`), not a
        // `host` header — fall back to the URI host so those requests still match.
        let Some(host) = Self::request_host(req) else {
            return false;
        };
        let host = normalize_host(&host);

        if host != self.prod_host {
            return false;
        }

        req.uri().path().starts_with(&self.path_prefix)
    }

    fn target_uri(&self, req: &Request<Body>) -> Option<Uri> {
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");

        format!("{}{}", self.local_target, path_and_query)
            .parse::<Uri>()
            .ok()
    }
}

/// Per-request correlation for the recording phase: the original prod URL
/// and request headers, captured before any rewrite.
#[derive(Clone, Debug)]
struct RecordMeta {
    url: String,
    headers: Vec<HarHeader>,
    started_ms: u128,
}

#[derive(Clone, Debug)]
pub struct DevRedirect {
    rules: Vec<RedirectRule>,
    /// `--record <dir>`: write intercepted exchanges into a HAR file.
    recorder: Option<Arc<Recorder>>,
    /// `--replay <file>`: answer requests from a recorded session before the
    /// rules get a chance.
    replayer: Option<Arc<Replayer>>,
    /// CSP override and record metadata of the most recent matched request,
    /// consumed by `handle_response` of the same request.
    ///
    /// hudsucker clones the handler per request, so this must NOT be an
    /// accumulating structure: a queue would leak entries from the CONNECT
    /// phase into every clone (clones are made from the instance that already
    /// processed CONNECT). Overwriting the field in `handle_request` makes
    /// inherited values irrelevant.
    pending_csp: Option<CspOverride>,
    pending_record: Option<RecordMeta>,
}

impl DevRedirect {
    pub fn new(rules: Vec<RedirectRule>) -> Self {
        Self {
            rules,
            recorder: None,
            replayer: None,
            pending_csp: None,
            pending_record: None,
        }
    }

    pub fn with_fixtures(
        rules: Vec<RedirectRule>,
        recorder: Option<Arc<Recorder>>,
        replayer: Option<Arc<Replayer>>,
    ) -> Self {
        Self {
            rules,
            recorder,
            replayer,
            pending_csp: None,
            pending_record: None,
        }
    }

    pub fn rules(&self) -> &[RedirectRule] {
        &self.rules
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

        let body = if recorded.content.encoding.as_deref() == Some("base64") {
            base64::engine::general_purpose::STANDARD
                .decode(&recorded.content.text)
                .unwrap_or_default()
        } else {
            recorded.content.text.clone().into_bytes()
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
            url: original_url(req),
            headers: headers_to_har(req.headers()),
            started_ms: std::time::Instant::now().elapsed().as_millis()
                + std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0),
        })
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

    let host = RedirectRule::request_host(req).unwrap_or_default();
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

impl DevRedirect {
    fn matching_rule(&self, req: &Request<Body>) -> Option<&RedirectRule> {
        self.rules.iter().find(|rule| rule.matches_request(req))
    }

    fn matches_any_host(&self, host: &str) -> bool {
        self.rules.iter().any(|rule| rule.matches_host(host))
    }
}

impl HttpHandler for DevRedirect {
    async fn should_intercept_tls(
        &mut self,
        _ctx: &HttpContext,
        client_hello: hudsucker::rustls::server::ClientHello<'_>,
    ) -> bool {
        let Some(server_name) = client_hello.server_name() else {
            return false;
        };

        self.matches_any_host(server_name)
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

        self.pending_record = self
            .recorder
            .as_ref()
            .and_then(|_| Self::record_meta(&req));

        let pending_csp = self.rewrite_request(&mut req);

        self.pending_csp = pending_csp;

        RequestOrResponse::Request(req)
    }

    fn rewrite_request(&self, req: &mut Request<Body>) -> Option<CspOverride> {
        let matched = self.matching_rule(req);

        tracing::info!(
            method = %req.method(),
            host = ?req.headers().get(header::HOST),
            uri = %req.uri(),
            matches = matched.is_some(),
            "HTTP request"
        );

        let rule = matched?;

        let Some(new_uri) = rule.target_uri(req) else {
            tracing::error!(
                uri = ?req.uri(),
                "failed to construct local target URI"
            );

            return None;
        };

        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .to_string();

        *req.uri_mut() = new_uri;

        let host_value = match local_target_host(&rule.local_target) {
            Some(host) => host,
            None => {
                tracing::error!(
                    target = %rule.local_target,
                    "failed to extract local target host"
                );

                return None;
            }
        };

        if let Ok(value) = host_value.parse() {
            req.headers_mut().insert(header::HOST, value);
        }

        tracing::info!(
            host = %rule.prod_host,
            path = %path_and_query,
            target = %rule.local_target,
            "redirecting request to local dev server"
        );

        rule.csp_override.clone()
    }

    async fn handle_response_inner(&mut self, mut res: Response<Body>) -> Response<Body> {
        if let Some(csp_override) = self.pending_csp.take() {
            apply_csp_override(res.headers_mut(), &csp_override);

            tracing::info!(?csp_override, "csp override applied to redirected response");
        }

        // Recording needs the whole body, which means buffering: streaming
        // responses (SSE, long-poll) are not suitable for recording anyway.
        if let (Some(meta), Some(recorder)) =
            (self.pending_record.take(), self.recorder.clone())
        {
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

        let (parts, body) = res.into_parts();
        let bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                tracing::warn!(%err, url = %meta.url, "failed to buffer response for recording");
                return Response::from_parts(parts, Body::empty());
            }
        };

        recorder.record(
            "GET",
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

        Response::from_parts(parts, Body::from(bytes.to_vec()))
    }
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn normalize_path_prefix(path: &str) -> String {
    let mut value = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };

    if !value.starts_with('/') {
        value.insert(0, '/');
    }

    value
}

fn local_target_host(target: &str) -> Option<String> {
    let uri: Uri = target.parse().ok()?;
    let authority = uri.authority()?;

    Some(authority.as_str().to_string())
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
        );
        let req = Request::builder()
            .uri("https://example.com/app.js")
            .body(Body::empty())
            .unwrap();

        assert!(rule.matches_request(&req));
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
            ),
            RedirectRule::new(
                "example.com".into(),
                "/".into(),
                "http://127.0.0.1:2222".into(),
                Some(CspOverride::Policy("policy-b".into())),
            ),
            RedirectRule::new(
                "other.com".into(),
                "/".into(),
                "http://127.0.0.1:3333".into(),
                Some(CspOverride::Off),
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
            ),
            RedirectRule::new(
                "stripped.com".into(),
                "/".into(),
                "http://127.0.0.1:2222".into(),
                Some(CspOverride::Off),
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

    // ---- record/replay fixtures ----

    fn recorded_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rexy-handler-har-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fixture_handler(dir: &std::path::Path, record: bool) -> DevRedirect {
        use crate::fixtures::Recorder;

        let (recorder, replayer) = if record {
            (Some(Arc::new(Recorder::start(dir).unwrap())), None)
        } else {
            (
                None,
                Some(Arc::new(
                    crate::fixtures::Replayer::open(&dir.join("rexy-session.har")).unwrap(),
                )),
            )
        };

        DevRedirect::with_fixtures(
            vec![RedirectRule::new(
                "a.example.com".into(),
                "/".into(),
                "http://127.0.0.1:1111".into(),
                None,
            )],
            recorder,
            replayer,
        )
    }

    #[tokio::test]
    async fn replay_answers_recorded_url_before_rules() {
        let dir = recorded_dir();
        // Record one exchange first.
        {
            let mut h = fixture_handler(&dir, true);
            let _ = h.handle_request_inner(request_to("a.example.com", "/api/data"));
            let res = Response::builder()
                .status(200)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(String::from("{\"ok\":true}")))
                .unwrap();
            h.handle_response_inner(res).await;
        }

        // Replay: the recorded URL is answered without touching the rules.
        let mut h = fixture_handler(&dir, false);
        let RequestOrResponse::Response(res) =
            h.handle_request_inner(request_to("a.example.com", "/api/data"))
        else {
            panic!("a recorded URL must be answered from fixtures");
        };
        assert_eq!(res.status(), 200);
        assert_eq!(res.headers()[header::CONTENT_TYPE], "application/json");

        // A different URL falls through to the rules (rewritten to the target).
        let RequestOrResponse::Request(req) =
            h.handle_request_inner(request_to("a.example.com", "/other"))
        else {
            panic!("unrecorded URLs must follow the rules");
        };
        assert_eq!(req.uri().to_string(), "http://127.0.0.1:1111/other");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn record_writes_har_with_body() {
        use base64::Engine;

        let dir = recorded_dir();
        let mut h = fixture_handler(&dir, true);

        let _ = h.handle_request_inner(request_to("a.example.com", "/api/data"));
        let res = Response::builder()
            .status(201)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(String::from("hello")))
            .unwrap();
        h.handle_response_inner(res).await;

        let raw = std::fs::read_to_string(dir.join("rexy-session.har")).unwrap();
        assert!(raw.contains("/api/data"));
        assert!(raw.contains(r#""status": 201"#));
        // base64("hello")
        assert!(raw.contains(&base64::engine::general_purpose::STANDARD.encode("hello")));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn matches_any_host_across_rules() {
        let h = multi_rule_handler();

        assert!(h.matches_any_host("example.com"));
        assert!(h.matches_any_host("other.com"));
        assert!(!h.matches_any_host("third.com"));
    }
}
