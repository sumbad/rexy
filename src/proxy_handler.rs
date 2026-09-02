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

    fn matches_host(&self, host: &str) -> bool {
        normalize_host(host) == self.prod_host
    }

    fn matches_request(&self, req: &Request<Body>) -> bool {
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(normalize_host);

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
        RequestOrResponse::Request(self.handle_request_inner(req))
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        self.handle_response_inner(res)
    }
}

impl DevRedirect {
    fn handle_request_inner(&mut self, mut req: Request<Body>) -> Request<Body> {
        let pending_csp = self.rewrite_request(&mut req);

        self.pending_csp = pending_csp;

        req
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

        let Some(rule) = matched else {
            return None;
        };

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

        let req = h.handle_request_inner(request_to("example.com", "/app/main.js"));
        assert_eq!(req.uri().to_string(), "http://127.0.0.1:1111/app/main.js");

        let res = h.handle_response_inner(response_with_csp("frame-ancestors 'self'"));

        assert_eq!(res.headers()[header::CONTENT_SECURITY_POLICY], "policy-a");
    }

    #[test]
    fn redirect_uses_matched_rule_target() {
        let mut h = multi_rule_handler();

        let req = h.handle_request_inner(request_to("example.com", "/other.js"));
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
