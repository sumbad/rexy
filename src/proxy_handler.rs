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

    /// Directory of a Map Local target (`target = "file:<dir>"`), if this
    /// rule serves static files instead of redirecting to a dev server.
    pub fn file_dir(&self) -> Option<&str> {
        self.local_target.strip_prefix("file:")
    }

    fn is_file_target(&self) -> bool {
        self.file_dir().is_some()
    }

    fn matches_request(&self, req: &Request<Body>) -> bool {
        // HTTP/2 requests carry the authority in the URI (`:authority`), not a
        // `host` header — fall back to the URI host so those requests still match.
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(normalize_host)
            .or_else(|| req.uri().host().map(normalize_host));

        let Some(host) = host else {
            return false;
        };

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

#[derive(Clone, Debug)]
pub struct DevRedirect {
    rules: Vec<RedirectRule>,
    /// CSP override of the most recent matched request, consumed by
    /// `handle_response` of the same request.
    ///
    /// hudsucker clones the handler per request, so this must NOT be an
    /// accumulating structure: a queue would leak entries from the CONNECT
    /// phase into every clone (clones are made from the instance that already
    /// processed CONNECT). Overwriting the field in `handle_request` makes
    /// inherited values irrelevant.
    pending_csp: Option<CspOverride>,
}

impl DevRedirect {
    pub fn new(rules: Vec<RedirectRule>) -> Self {
        Self {
            rules,
            pending_csp: None,
        }
    }

    pub fn rules(&self) -> &[RedirectRule] {
        &self.rules
    }

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
        self.handle_response_inner(res)
    }
}

impl DevRedirect {
    fn handle_request_inner(&mut self, mut req: Request<Body>) -> RequestOrResponse {
        let matched = self.matching_rule(&req);

        tracing::info!(
            method = %req.method(),
            host = ?req.headers().get(header::HOST),
            uri = %req.uri(),
            matches = matched.is_some(),
            "HTTP request"
        );

        let Some(rule) = matched else {
            self.pending_csp = None;
            return RequestOrResponse::Request(req);
        };

        // Map Local: a `file:` target serves static files directly instead of
        // redirecting to a dev server. The response is built here, so its
        // CSP override is applied here too — `handle_response` never sees it.
        if rule.is_file_target() {
            let mut res = serve_from_file_target(rule, &req);

            if let Some(csp_override) = rule.csp_override() {
                apply_csp_override(res.headers_mut(), csp_override);
                tracing::info!(?csp_override, "csp override applied to file-target response");
            }

            return RequestOrResponse::Response(res);
        }

        let pending_csp = self.rewrite_request(rule, &mut req);

        self.pending_csp = pending_csp;

        RequestOrResponse::Request(req)
    }

    fn rewrite_request(&self, rule: &RedirectRule, req: &mut Request<Body>) -> Option<CspOverride> {
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

    fn handle_response_inner(&mut self, mut res: Response<Body>) -> Response<Body> {
        if let Some(csp_override) = self.pending_csp.take() {
            apply_csp_override(res.headers_mut(), &csp_override);

            tracing::info!(?csp_override, "csp override applied to redirected response");
        }

        res
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

fn plain_response(status: hudsucker::hyper::StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, body.len())
        .body(Body::from(body.to_string()))
        .expect("static response with fixed parts always builds")
}

/// Map Local: serve a request from the `file:<dir>` target's directory by the
/// requested path — the cheap way to put local assets on top of prod without
/// a dev server. `..` segments and symlink escapes are rejected; directories
/// are not listed; the query string is not part of the lookup.
fn serve_from_file_target(rule: &RedirectRule, req: &Request<Body>) -> Response<Body> {
    use hudsucker::hyper::{Method, StatusCode};
    use std::path::PathBuf;

    let dir = rule.file_dir().expect("file target checked by caller");
    let head = req.method() == Method::HEAD;

    if req.method() != Method::GET && !head {
        return plain_response(StatusCode::METHOD_NOT_ALLOWED, "only GET and HEAD are served\n");
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

    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime_type(&canonical))
        .header(header::CONTENT_LENGTH, bytes.len());

    if head {
        builder.body(Body::empty())
    } else {
        builder.body(Body::from(bytes))
    }
    .expect("static response with fixed parts always builds")
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

    #[test]
    fn response_for_redirected_request_gets_override() {
        let mut h = handler(Some(CspOverride::Off));

        let req = request_to("example.com", "/app.js");
        let _ = h.handle_request_inner(req);

        let res = h.handle_response_inner(response_with_csp("frame-ancestors 'self'"));

        assert!(!res.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    }

    #[test]
    fn response_for_passthrough_request_is_untouched() {
        let mut h = handler(Some(CspOverride::Off));

        let req = request_to("other.com", "/app.js");
        let _ = h.handle_request_inner(req);

        let res = h.handle_response_inner(response_with_csp("frame-ancestors 'self'"));

        assert_eq!(
            res.headers()[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'self'"
        );
    }

    #[test]
    fn response_without_override_keeps_csp() {
        let mut h = handler(None);

        let req = request_to("example.com", "/app.js");
        let _ = h.handle_request_inner(req);

        let res = h.handle_response_inner(response_with_csp("frame-ancestors 'self'"));

        assert_eq!(
            res.headers()[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'self'"
        );
    }

    #[test]
    fn response_without_prior_request_is_untouched() {
        let mut h = handler(Some(CspOverride::Off));

        let res = h.handle_response_inner(response_with_csp("frame-ancestors 'self'"));

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
        for path in ["/../secret.txt", "/a/../../secret.txt", "/%2e%2e/secret.txt"] {
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
        assert_eq!(res.headers()[header::CONTENT_TYPE], "text/plain; charset=utf-8");

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
        )]);

        let res = as_response(h.handle_request_inner(file_request("/app.js")));
        assert_eq!(res.status(), 200);
        assert!(!res.headers().contains_key(header::CONTENT_SECURITY_POLICY));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn non_redirected_state_does_not_leak_into_cloned_handler() {
        // Real hudsucker flow: one handler instance processes the CONNECT
        // request (no redirect), then `serve_stream` clones that instance for
        // every decrypted inner request. The clone must not inherit the
        // non-redirected outcome: its own request decides.
        let mut connect_handler = handler(Some(CspOverride::Off));
        let _ = connect_handler.handle_request_inner(request_to("other.com", "/"));

        let mut inner = connect_handler.clone();
        let _ = inner.handle_request_inner(request_to("example.com", "/"));

        let res = inner.handle_response_inner(response_with_csp("frame-ancestors 'self'"));

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

    #[test]
    fn first_matching_rule_wins() {
        let mut h = multi_rule_handler();

        let RequestOrResponse::Request(req) =
            h.handle_request_inner(request_to("example.com", "/app/main.js"))
        else {
            panic!("redirect rules must pass the request through");
        };
        assert_eq!(req.uri().to_string(), "http://127.0.0.1:1111/app/main.js");

        let res = h.handle_response_inner(response_with_csp("frame-ancestors 'self'"));

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

    #[test]
    fn per_rule_csp_isolated() {
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

        let res = h.handle_response_inner(response_with_csp("frame-ancestors 'self'"));

        assert_eq!(
            res.headers()[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'self'"
        );
    }

    #[test]
    fn matches_any_host_across_rules() {
        let h = multi_rule_handler();

        assert!(h.matches_any_host("example.com"));
        assert!(h.matches_any_host("other.com"));
        assert!(!h.matches_any_host("third.com"));
    }
}
