use std::path::Path;

use serde::Deserialize;

use crate::rules::{CspOverride, RedirectRule};

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

    let rules: Vec<RedirectRule> = parsed
        .rules
        .into_iter()
        .enumerate()
        .map(|(index, rule)| rule_from_file(rule, index))
        .collect::<Result<_, _>>()?;

    warn_shadowed_rules(&rules);

    Ok(rules)
}

/// Pairs of rule indices where the earlier rule (first-match-wins) shadows a
/// later one: same host, and the earlier path prefix covers the later rule's
/// path — including equal paths (a duplicate host+path). Hosts and paths come
/// from `RedirectRule` accessors, already normalized exactly like the matcher
/// normalizes them.
fn shadowed_pairs(rules: &[RedirectRule]) -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();

    for (later_idx, later) in rules.iter().enumerate() {
        for (earlier_idx, earlier) in rules.iter().enumerate().take(later_idx) {
            if earlier.host() == later.host() && later.path().starts_with(earlier.path()) {
                pairs.push((earlier_idx, later_idx));
            }
        }
    }

    pairs
}

fn warn_shadowed_rules(rules: &[RedirectRule]) {
    for (earlier, later) in shadowed_pairs(rules) {
        tracing::warn!(
            earlier = format!("#{} {}{}", earlier + 1, rules[earlier].host(), rules[earlier].path()),
            later = format!("#{} {}{}", later + 1, rules[later].host(), rules[later].path()),
            "rule is shadowed: the earlier rule matches first (first-match-wins), \
             so the later rule never fires for these paths — \
             reorder rules so the more specific path comes first"
        );
    }
}

fn rule_from_file(
    rule: FileRule,
    index: usize,
) -> Result<RedirectRule, Box<dyn std::error::Error>> {
    let host = interpolate_field(&rule.host, index, "host")?;
    let path = interpolate_field(&rule.path, index, "path")?;
    let target = interpolate_field(&rule.target, index, "target")?;
    let csp_override = rule
        .csp_override
        .as_deref()
        .map(|raw| interpolate_field(raw, index, "csp_override"))
        .transpose()?;

    validate_host(&host)?;
    validate_path(&path)?;
    validate_target(&target)?;

    let csp_override = csp_override.map(|value| parse_csp_value(&value)).transpose()?;

    Ok(RedirectRule::new(host, path, target, csp_override))
}

/// Expand environment variable references in a rule field, after TOML parsing
/// (so an expanded value can never break the file's structure).
///
/// Supported syntax (bracketed form only, like Docker Compose):
/// - `${VAR}` — the variable's value; an unset variable without a default is
///   a load error naming the variable and the rule;
/// - `${VAR:-default}` — the variable's value, or `default` when unset or
///   empty-free (an empty value is a value, not an error);
/// - `$$` — a literal `$`, so `$${VAR}` stays a literal `${VAR}`;
/// - a bare `$VAR` (no braces) is NOT interpolated — `$` outside `${` is a
///   literal dollar sign.
fn interpolate_field(input: &str, rule_index: usize, field: &str) -> Result<String, String> {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '$' {
            out.push(ch);
            continue;
        }

        match chars.peek() {
            Some('$') => {
                chars.next();
                out.push('$');
            }
            Some('{') => {
                chars.next();

                let mut expr = String::new();
                loop {
                    match chars.next() {
                        None => {
                            return Err(format!(
                                "unterminated ${{…}} — missing '}}' after '${{{expr}"
                            ));
                        }
                        Some('}') => break,
                        Some(c) => expr.push(c),
                    }
                }

                out.push_str(&expand_expr(&expr, rule_index, field)?);
            }
            _ => out.push('$'),
        }
    }

    Ok(out)
}

/// Expand one `${…}` expression body: `VAR` or `VAR:-default`.
fn expand_expr(expr: &str, rule_index: usize, field: &str) -> Result<String, String> {
    let (name, default) = match expr.split_once(":-") {
        Some((name, default)) => (name, Some(default)),
        None => (expr, None),
    };

    let invalid_name = || {
        format!(
            "invalid variable name {:?} in ${{{expr}}} — \
             expected letters, digits or '_' and a non-empty name",
            name
        )
    };

    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(invalid_name());
    }

    match std::env::var(name) {
        Ok(value) => {
            if value.is_empty() {
                // `${VAR:-default}` also covers an empty value (bash `:-`
                // semantics); an empty value with no default stays empty.
                match default {
                    Some(default) => Ok(default.to_string()),
                    None => Ok(value),
                }
            } else {
                Ok(value)
            }
        }
        Err(std::env::VarError::NotPresent) => match default {
            Some(default) => Ok(default.to_string()),
            None => Err(format!(
                "environment variable {name} is not set (referenced by field {field:?} \
                 of rule #{}, as ${{{expr}}})",
                rule_index + 1
            )),
        },
        Err(err @ std::env::VarError::NotUnicode(_)) => Err(err.to_string()),
    }
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

    fn rule(host: &str, path: &str) -> RedirectRule {
        RedirectRule::new(host.into(), path.into(), "http://127.0.0.1:1111".into(), None)
    }

    #[test]
    fn shadowing_is_detected_for_specific_rule_after_generic() {
        let rules = vec![
            rule("app.example.com", "/api/"),
            rule("app.example.com", "/api/v1/omicron/get"),
        ];

        assert_eq!(shadowed_pairs(&rules), vec![(0, 1)]);
    }

    #[test]
    fn shadowing_is_detected_for_duplicate_rules() {
        let rules = vec![rule("app.example.com", "/api/"), rule("app.example.com", "/api/")];

        assert_eq!(shadowed_pairs(&rules), vec![(0, 1)]);
    }

    #[test]
    fn specific_rule_first_is_not_shadowing() {
        let rules = vec![
            rule("app.example.com", "/api/v1/omicron/get"),
            rule("app.example.com", "/api/"),
        ];

        assert!(shadowed_pairs(&rules).is_empty());
    }

    #[test]
    fn different_or_uncomparable_hosts_are_silent() {
        let rules = vec![
            rule("app.example.com", "/"),
            rule("other.example.com", "/"),
            rule("app.example.com", "/api/"),
        ];

        // app /  shadows app /api/ ; other /  is a different host — no pair.
        assert_eq!(shadowed_pairs(&rules), vec![(0, 2)]);
    }

    #[test]
    fn prefix_paths_of_same_host_are_comparable() {
        // "/app" prefix covers "/apple" too — the later rule is unreachable.
        let rules = vec![rule("app.example.com", "/app"), rule("app.example.com", "/apple")];

        assert_eq!(shadowed_pairs(&rules), vec![(0, 1)]);
    }

    #[test]
    fn shorter_but_not_prefix_path_is_silent() {
        // "/api/" does not cover "/api" (no trailing slash in the later rule).
        let rules = vec![rule("app.example.com", "/api/"), rule("app.example.com", "/api")];

        assert!(shadowed_pairs(&rules).is_empty());
    }

    #[test]
    fn load_rules_logs_without_failing_on_shadowing() {
        // Shadowing is a warning, not an error: the config still loads.
        let path = write_temp_config(
            r#"
[[rules]]
host = "app.example.com"
path = "/api/"
target = "http://127.0.0.1:1111"

[[rules]]
host = "app.example.com"
path = "/api/v1/omicron/get"
target = "http://127.0.0.1:8124"
"#,
        );

        let rules = load_rules(&path).unwrap();

        assert_eq!(rules.len(), 2);
        assert_eq!(shadowed_pairs(&rules), vec![(0, 1)]);

        std::fs::remove_file(&path).ok();
    }

    // Environment mutation is process-global: every env-dependent scenario
    // runs inside ONE test so parallel tests cannot race on the variables.
    #[test]
    fn interpolation_with_environment() {
        unsafe {
            std::env::set_var("REXY_TEST_HOST", "prod.example.com");
            std::env::set_var("REXY_TEST_PORT", "8123");
            std::env::set_var("REXY_TEST_EMPTY", "");
        }
        let set = |name: &str| unsafe { std::env::remove_var(name) };

        // Present variable expands.
        assert_eq!(
            interpolate_field("${REXY_TEST_HOST}/api/", 0, "path").unwrap(),
            "prod.example.com/api/"
        );

        // Default used when unset...
        set("REXY_TEST_UNSET");
        assert_eq!(
            interpolate_field("${REXY_TEST_UNSET:-8124}", 0, "path").unwrap(),
            "8124"
        );
        // ...and when set-but-empty (bash `:-` semantics)...
        assert_eq!(
            interpolate_field("127.0.0.1:${REXY_TEST_EMPTY:-8124}", 0, "target").unwrap(),
            "127.0.0.1:8124"
        );
        // ...while a present value wins over the default.
        assert_eq!(
            interpolate_field("127.0.0.1:${REXY_TEST_PORT:-9999}", 0, "target").unwrap(),
            "127.0.0.1:8123"
        );

        // Empty value with no default expands to empty, without an error.
        assert_eq!(interpolate_field("x${REXY_TEST_EMPTY}y", 0, "path").unwrap(), "xy");

        // Unset without default — error naming the variable, rule and field.
        let err = interpolate_field("${REXY_TEST_UNSET}", 2, "target").unwrap_err();
        assert!(err.contains("REXY_TEST_UNSET"), "{err}");
        assert!(err.contains("#3"), "{err}");
        assert!(err.contains("target"), "{err}");

        // Bare $VAR is NOT interpolated; $ outside ${...} is literal.
        assert_eq!(interpolate_field("$REXY_TEST_HOST", 0, "path").unwrap(), "$REXY_TEST_HOST");
        assert_eq!(interpolate_field("price $5", 0, "path").unwrap(), "price $5");
        assert_eq!(interpolate_field("trailing $", 0, "path").unwrap(), "trailing $");

        // `$$` escapes a literal `$`; `$${VAR}` stays literal `${VAR}`.
        assert_eq!(interpolate_field("$$8123", 0, "path").unwrap(), "$8123");
        assert_eq!(
            interpolate_field("$${REXY_TEST_HOST}", 0, "path").unwrap(),
            "${REXY_TEST_HOST}"
        );

        // Malformed references are errors.
        assert!(interpolate_field("${REXY_TEST_HOST", 0, "path").is_err()); // unterminated
        assert!(interpolate_field("${}", 0, "path").is_err()); // empty name
        assert!(interpolate_field("${1BAD}", 0, "path").is_err()); // bad name chars
    }

    #[test]
    fn interpolation_neutral_without_dollar() {
        // Configs without `${…}` parse exactly as before.
        assert_eq!(interpolate_field("app.example.com", 0, "host").unwrap(), "app.example.com");
        assert_eq!(interpolate_field("/api/v1/", 3, "path").unwrap(), "/api/v1/");
        assert_eq!(interpolate_field("", 0, "csp_override").unwrap(), "");
    }

    #[test]
    fn load_rules_expands_environment_in_fields() {
        unsafe {
            std::env::set_var("REXY_TEST_RULES_HOST", "a.example.com");
            std::env::set_var("REXY_TEST_RULES_CSP", "frame-ancestors *");
        }

        let path = write_temp_config(
            r#"
[[rules]]
host = "${REXY_TEST_RULES_HOST}"
target = "http://127.0.0.1:${REXY_TEST_RULES_PORT:-1111}"
csp_override = "${REXY_TEST_RULES_CSP}"
"#,
        );

        let rules = load_rules(&path).unwrap();

        assert_eq!(rules[0].host(), "a.example.com");
        assert_eq!(rules[0].target(), "http://127.0.0.1:1111");
        assert_eq!(
            rules[0].csp_override(),
            Some(&CspOverride::Policy("frame-ancestors *".into()))
        );

        unsafe {
            std::env::remove_var("REXY_TEST_RULES_HOST");
            std::env::remove_var("REXY_TEST_RULES_CSP");
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_rules_fails_when_variable_is_unset() {
        let path = write_temp_config(
            r#"
[[rules]]
host = "${REXY_TEST_DEFINITELY_UNSET_VAR}"
target = "http://127.0.0.1:1111"
"#,
        );

        let err = load_rules(&path).unwrap_err().to_string();
        assert!(err.contains("REXY_TEST_DEFINITELY_UNSET_VAR"), "{err}");
        assert!(err.contains("#1"), "{err}");

        std::fs::remove_file(&path).ok();
    }
}
