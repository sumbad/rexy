/// How to rewrite the `Content-Security-Policy` header of responses served
/// from the local target. Parsed from `rexy run --csp-override`.
#[derive(Clone, Debug, PartialEq)]
pub enum CspOverride {
    /// Remove all Content-Security-Policy headers.
    Off,
    /// Replace all Content-Security-Policy headers with this policy string.
    Policy(String),
}

/// One redirect rule: which host/path prefix to intercept and which local
/// target to serve it from.
///
/// The matching logic here (`matches`) is the single source of truth shared
/// by the proxy request path and the offline `rexy rules check` command.
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
            prod_host: normalize_host(&prod_host),
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

    /// Shared matcher: exact host (normalized) plus path-prefix match.
    ///
    /// The host must already be extracted from the request (`host` header,
    /// URI authority) or the URL; query strings are not part of the path.
    pub fn matches(&self, host: &str, path: &str) -> bool {
        normalize_host(host) == self.prod_host && path.starts_with(&self.path_prefix)
    }

    pub(crate) fn matches_host(&self, host: &str) -> bool {
        normalize_host(host) == self.prod_host
    }
}

pub(crate) fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

pub(crate) fn normalize_path_prefix(path: &str) -> String {
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

pub(crate) fn local_target_host(target: &str) -> Option<String> {
    let uri: hudsucker::hyper::Uri = target.parse().ok()?;
    let authority = uri.authority()?;

    Some(authority.as_str().to_string())
}

impl RedirectRule {
    /// URI the request would be rewritten to: target plus the request's
    /// path-and-query.
    pub(crate) fn target_uri(&self, path_and_query: &str) -> Option<hudsucker::hyper::Uri> {
        format!("{}{}", self.local_target, path_and_query)
            .parse()
            .ok()
    }
}

/// Outcome of an offline `rexy rules check` evaluation for one URL.
#[derive(Clone, Debug, serde::Serialize)]
pub struct CheckOutcome {
    pub url: String,
    pub matched: bool,
    /// Zero-based index of the matching rule (`#N` in text output is index+1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// CSP override of the matched rule: `"off"` or the policy string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csp_override: Option<String>,
}

/// Evaluate one URL against the rules exactly like the proxy would: extract
/// host and path from the URL (scheme optional, `https` assumed; query string
/// is not part of matching), then apply the shared first-match-wins matcher.
pub fn check_url(rules: &[RedirectRule], url: &str) -> Result<CheckOutcome, String> {
    let (host, path) = split_url(url)?;

    let outcome = rules.iter().enumerate().find_map(|(index, rule)| {
        rule.matches(&host, &path).then(|| CheckOutcome {
            url: url.to_string(),
            matched: true,
            rule_index: Some(index),
            rule_host: Some(rule.host().to_string()),
            rule_path: Some(rule.path().to_string()),
            target: Some(rule.target().to_string()),
            csp_override: rule.csp_override().map(|csp| match csp {
                CspOverride::Off => "off".to_string(),
                CspOverride::Policy(policy) => policy.clone(),
            }),
        })
    });

    Ok(outcome.unwrap_or(CheckOutcome {
        url: url.to_string(),
        matched: false,
        rule_index: None,
        rule_host: None,
        rule_path: None,
        target: None,
        csp_override: None,
    }))
}

/// Split a URL into `(host, path)` for the shared matcher.
fn split_url(url: &str) -> Result<(String, String), String> {
    let candidate = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{url}")
    };

    let uri: hudsucker::hyper::Uri = candidate
        .parse()
        .map_err(|err| format!("invalid URL {url:?}: {err}"))?;

    let host = uri
        .host()
        .ok_or_else(|| format!("URL {url:?} has no hostname"))?
        .to_string();

    let path = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };

    Ok((host, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(host: &str, path: &str, target: &str) -> RedirectRule {
        RedirectRule::new(host.into(), path.into(), target.into(), None)
    }

    #[test]
    fn matches_normalizes_host_and_path() {
        let r = rule("Example.COM.", "/app/", "http://127.0.0.1:1111");

        assert!(r.matches("example.com", "/app/main.js"));
        assert!(r.matches("example.com:443", "/app/"));
        assert!(r.matches("  EXAMPLE.com  ", "/app/x"));
        assert!(!r.matches("example.com", "/other"));
        assert!(!r.matches("other.com", "/app/"));
    }

    #[test]
    fn matches_exact_host_without_subdomains() {
        let r = rule("example.com", "/", "http://127.0.0.1:1111");

        assert!(!r.matches("sub.example.com", "/"));
    }

    #[test]
    fn path_prefix_is_stripped_of_query() {
        // The caller passes the path only (no query); a rule path itself is
        // matched as a literal prefix.
        let r = rule("example.com", "/api/", "http://127.0.0.1:1111");

        assert!(r.matches("example.com", "/api/v1/get"));
        assert!(!r.matches("example.com", "/api"));
    }

    #[test]
    fn rule_construction_normalizes_inputs() {
        let r = rule("Example.COM.", "app", "http://127.0.0.1:1111/");

        assert_eq!(r.host(), "example.com");
        assert_eq!(r.path(), "/app");
        assert_eq!(r.target(), "http://127.0.0.1:1111");
    }

    #[test]
    fn check_url_matches_first_rule_with_numbering() {
        let rules = vec![
            rule("app.example.com", "/api/v1/omicron/get", "http://127.0.0.1:8124"),
            rule("app.example.com", "/api/", "http://127.0.0.1:8123"),
            rule("other.example.com", "/", "http://127.0.0.1:5173"),
        ];

        let hit = check_url(&rules, "https://app.example.com/api/v1/omicron/get?x=1").unwrap();
        assert!(hit.matched);
        assert_eq!(hit.rule_index, Some(0));
        assert_eq!(hit.target.as_deref(), Some("http://127.0.0.1:8124"));

        let hit = check_url(&rules, "https://app.example.com/api/v2/list").unwrap();
        assert_eq!(hit.rule_index, Some(1));
        assert_eq!(hit.rule_path.as_deref(), Some("/api/"));

        let miss = check_url(&rules, "https://app.example.com/static/app.js").unwrap();
        assert!(!miss.matched);
        assert_eq!(miss.rule_index, None);
        assert_eq!(miss.target, None);
    }

    #[test]
    fn check_url_accepts_scheme_less_urls_and_strips_port() {
        let rules = vec![rule("app.example.com", "/", "http://127.0.0.1:8123")];

        let hit = check_url(&rules, "app.example.com:443/app/main.js").unwrap();
        assert!(hit.matched);

        let miss = check_url(&rules, "https://sub.app.example.com/").unwrap();
        assert!(!miss.matched);
    }

    #[test]
    fn check_url_reports_invalid_input() {
        let rules = vec![rule("app.example.com", "/", "http://127.0.0.1:8123")];

        // No hostname at all.
        assert!(check_url(&rules, "https://").is_err());
        // Scheme-less input with no host either.
        assert!(check_url(&rules, "/api/v1/get").is_err());
        // Scheme is ignored: host + path decide, like in the proxy.
        assert!(check_url(&rules, "ftp://app.example.com/").is_ok());
    }

    #[test]
    fn check_url_serializes_unmatched_compactly() {
        let rules = vec![];

        let outcome = check_url(&rules, "https://a.example.com/x").unwrap();
        let json = serde_json::to_value(&outcome).unwrap();

        assert_eq!(
            json,
            serde_json::json!({"url": "https://a.example.com/x", "matched": false})
        );
    }
}
