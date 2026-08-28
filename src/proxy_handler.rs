use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{Request, Uri, header},
};

#[derive(Clone, Debug)]
pub struct DevRedirect {
    prod_host: String,
    path_prefix: String,
    local_target: String,
}

impl DevRedirect {
    pub fn new(prod_host: String, path_prefix: String, local_target: String) -> Self {
        Self {
            prod_host: prod_host.trim_end_matches('.').to_ascii_lowercase(),
            path_prefix: normalize_path_prefix(&path_prefix),
            local_target: local_target.trim_end_matches('/').to_string(),
        }
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

impl HttpHandler for DevRedirect {
    async fn should_intercept_tls(
        &mut self,
        _ctx: &HttpContext,
        client_hello: hudsucker::rustls::server::ClientHello<'_>,
    ) -> bool {
        let Some(server_name) = client_hello.server_name() else {
            return false;
        };

        self.matches_host(server_name)
    }

    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: Request<Body>,
    ) -> RequestOrResponse {
        tracing::info!(
            method = %req.method(),
            host = ?req.headers().get(header::HOST),
            uri = %req.uri(),
            matches = self.matches_request(&req),
            "HTTP request"
        );

        if !self.matches_request(&req) {
            return RequestOrResponse::Request(req);
        }

        let Some(new_uri) = self.target_uri(&req) else {
            tracing::error!(
                uri = ?req.uri(),
                "failed to construct local target URI"
            );

            return RequestOrResponse::Request(req);
        };

        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .to_string();

        *req.uri_mut() = new_uri;

        let host_value = match local_target_host(&self.local_target) {
            Some(host) => host,
            None => {
                tracing::error!(
                    target = %self.local_target,
                    "failed to extract local target host"
                );

                return RequestOrResponse::Request(req);
            }
        };

        if let Ok(value) = host_value.parse() {
            req.headers_mut().insert(header::HOST, value);
        }

        tracing::info!(
            host = %self.prod_host,
            path = %path_and_query,
            target = %self.local_target,
            "redirecting request to local dev server"
        );

        RequestOrResponse::Request(req)
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
