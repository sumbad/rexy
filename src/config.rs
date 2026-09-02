use std::path::Path;

use serde::Deserialize;

use crate::proxy_handler::{CspOverride, RedirectRule};

#[derive(Debug, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    rules: Vec<FileRule>,
}

#[derive(Debug, Deserialize)]
struct FileRule {
    host: String,
    #[serde(default = "default_path")]
    path: String,
    target: String,
    #[serde(default)]
    csp_override: Option<String>,
}

fn default_path() -> String {
    "/".to_string()
}

/// Load and validate redirect rules from a TOML config file.
///
/// An empty (or absent) `[[rules]]` list is valid and yields no rules; the
/// caller decides how to behave (rexy logs a warning and runs without
/// redirects).
pub fn load_rules(path: &Path) -> Result<Vec<RedirectRule>, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read config file {}: {err}", path.display()))?;

    let parsed: ConfigFile = toml::from_str(&raw)
        .map_err(|err| format!("failed to parse config file {}: {err}", path.display()))?;

    parsed.rules.into_iter().map(rule_from_file).collect()
}

fn rule_from_file(rule: FileRule) -> Result<RedirectRule, Box<dyn std::error::Error>> {
    validate_host(&rule.host)?;
    validate_path(&rule.path)?;
    validate_target(&rule.target)?;

    let csp_override = rule
        .csp_override
        .as_deref()
        .map(parse_csp_value)
        .transpose()?;

    Ok(RedirectRule::new(
        rule.host,
        rule.path,
        rule.target,
        csp_override,
    ))
}

/// Parse the CSP override value shared by the CLI flag and config entries:
/// `off` removes the header, any other string replaces it.
pub fn parse_csp_value(value: &str) -> Result<CspOverride, Box<dyn std::error::Error>> {
    let value = value.trim();

    if value.is_empty() {
        return Err("csp override cannot be empty: pass a policy or 'off'".into());
    }

    if value.eq_ignore_ascii_case("off") {
        return Ok(CspOverride::Off);
    }

    // Rejects newlines and non-visible-ASCII bytes (header injection guard).
    if hudsucker::hyper::header::HeaderValue::from_str(value).is_err() {
        return Err(format!(
            "csp override contains characters invalid for an HTTP header: {value:?}"
        )
        .into());
    }

    Ok(CspOverride::Policy(value.to_string()))
}

pub fn validate_host(host: &str) -> Result<(), Box<dyn std::error::Error>> {
    if host.is_empty() {
        return Err("host cannot be empty".into());
    }

    if host.contains("://") {
        return Err("host must contain only hostname, e.g. superapp.example.com".into());
    }

    if host.contains('/') {
        return Err("host must not contain a path".into());
    }

    Ok(())
}

pub fn validate_path(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !path.starts_with('/') {
        return Err("path must start with '/'".into());
    }

    Ok(())
}

pub fn validate_target(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parsed: hudsucker::hyper::Uri = target.parse()?;

    match parsed.scheme_str() {
        Some("http" | "https") => {}
        _ => {
            return Err("target must be an http:// or https:// URL".into());
        }
    }

    if parsed.host().is_none() {
        return Err("target must contain a hostname".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp_config(content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rexy-config-test-{}-{}.toml",
            std::process::id(),
            content.len()
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn loads_multiple_rules_with_defaults() {
        let path = write_temp_config(
            r#"
[[rules]]
host = "a.example.com"
target = "http://127.0.0.1:1111"

[[rules]]
host = "b.example.com"
path = "/app/"
target = "http://127.0.0.1:2222"
csp_override = "off"
"#,
        );

        let rules = load_rules(&path).unwrap();

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].host(), "a.example.com");
        assert_eq!(rules[0].path(), "/");
        assert_eq!(rules[0].target(), "http://127.0.0.1:1111");
        assert_eq!(rules[0].csp_override(), None);
        assert_eq!(rules[1].host(), "b.example.com");
        assert_eq!(rules[1].path(), "/app/");
        assert_eq!(rules[1].target(), "http://127.0.0.1:2222");
        assert_eq!(rules[1].csp_override(), Some(&CspOverride::Off));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn csp_override_policy_is_parsed() {
        let path = write_temp_config(
            r#"
[[rules]]
host = "a.example.com"
target = "http://127.0.0.1:1111"
csp_override = "frame-ancestors *"
"#,
        );

        let rules = load_rules(&path).unwrap();

        assert_eq!(
            rules[0].csp_override(),
            Some(&CspOverride::Policy("frame-ancestors *".into()))
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_rules_list_is_ok() {
        let path = write_temp_config("rules = []\n");
        assert_eq!(load_rules(&path).unwrap().len(), 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(load_rules(Path::new("/nonexistent/rexy/rules.toml")).is_err());
    }

    #[test]
    fn missing_required_field_is_an_error() {
        let path = write_temp_config(
            r#"
[[rules]]
host = "a.example.com"
"#,
        );

        assert!(load_rules(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_invalid_host() {
        let path = write_temp_config(
            r#"
[[rules]]
host = "https://a.example.com"
target = "http://127.0.0.1:1111"
"#,
        );

        assert!(load_rules(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_invalid_target() {
        let path = write_temp_config(
            r#"
[[rules]]
host = "a.example.com"
target = "ftp://127.0.0.1:1111"
"#,
        );

        assert!(load_rules(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_invalid_csp_override() {
        let path = write_temp_config(
            r#"
[[rules]]
host = "a.example.com"
target = "http://127.0.0.1:1111"
csp_override = "frame-ancestors *\nX-Evil: y"
"#,
        );

        assert!(load_rules(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parse_csp_value_accepts_off_and_policy() {
        assert_eq!(parse_csp_value("off").unwrap(), CspOverride::Off);
        assert_eq!(
            parse_csp_value("frame-ancestors *").unwrap(),
            CspOverride::Policy("frame-ancestors *".into())
        );
        assert!(parse_csp_value("   ").is_err());
        assert!(parse_csp_value("x\ny").is_err());
    }
}
