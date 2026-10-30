mod browser;
mod ca;
mod config;
mod pac;
mod proxy_handler;
mod rules;
mod trust;

use clap::{Parser, Subcommand};
use hudsucker::Proxy;
use rules::{CheckOutcome, RedirectRule};
use tokio::net::TcpListener;
use tracing::{error, info};

use browser::resolve_browser;
use hyper_rustls::ConfigBuilderExt;
use proxy_handler::DevRedirect;

#[derive(Debug, Parser)]
#[command(
    name = "rexy",
    version,
    about = "Launch a browser with a local MITM proxy for transparent dev redirects"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Launch the browser through the local proxy.
    Run(RunArgs),

    /// Install the Rexy Local CA into the OS trust store.
    Trust {
        /// Install into Firefox profiles (NSS) instead of the OS store.
        #[arg(long)]
        firefox: bool,
    },

    /// Remove the Rexy Local CA from the OS trust store.
    Clean {
        /// Remove from Firefox profiles (NSS) instead of the OS store.
        #[arg(long)]
        firefox: bool,
    },

    /// Work with redirect rules from a TOML file.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    /// Print which rule would match each URL — offline, no proxy or browser.
    Check {
        /// TOML file with [[rules]] entries.
        #[arg(short, long)]
        file: String,

        /// Emit JSON (one object per URL) instead of human-readable text.
        #[arg(long)]
        json: bool,

        /// URLs to check; the scheme is optional (https is assumed).
        #[arg(required = true)]
        urls: Vec<String>,
    },
}

#[derive(Debug, Parser)]
struct RunArgs {
    /// Browser to launch: chrome, chromium, or an executable path.
    #[arg(long, default_value = "chrome")]
    browser: String,

    /// TOML file with [[rules]] entries; replaces --host/--path/--target/--csp-override.
    #[arg(short, long)]
    file: Option<String>,

    /// Production hostname to intercept (single-rule mode).
    #[arg(long)]
    host: Option<String>,

    /// Production path prefix to redirect (single-rule mode).
    #[arg(long)]
    path: Option<String>,

    /// Local development server (single-rule mode).
    #[arg(long)]
    target: Option<String>,

    /// Local proxy port. 0 means choose a free port.
    #[arg(long, default_value_t = 0)]
    proxy_port: u16,

    /// Override the Content-Security-Policy of responses served from --target.
    /// Pass `off` to remove the header entirely. (single-rule mode)
    #[arg(long)]
    csp_override: Option<String>,

    /// Browser arguments after `--`.
    #[arg(last = true, trailing_var_arg = true)]
    browser_args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    let cli = Cli::parse();

    match cli.command {
        Some(Command::Trust { firefox }) => {
            if firefox {
                trust::install_firefox()?;
            } else {
                trust::install()?;
            }
            return Ok(());
        }

        Some(Command::Clean { firefox }) => {
            if firefox {
                trust::remove_firefox()?;
            } else {
                trust::remove()?;
            }
            return Ok(());
        }

    Some(Command::Run(args)) => run(args).await?,

    Some(Command::Rules { command }) => match command {
        RulesCommand::Check { file, json, urls } => rules_check(&file, json, &urls)?,
    },

    None => {
        println!("Use:");
        println!();
        println!("  rexy run --file <rules.toml>");
        println!("  rexy run --host <host> --path <path> --target <url> -- <browser args>");
        println!("  rexy rules check -f <rules.toml> <url>...");
        println!();
            println!("Example:");
            println!();
            println!("  rexy run \\");
            println!("    --browser chrome \\");
            println!("    --host superapp.example.com \\");
            println!("    --path /mini-app/ \\");
            println!("    --target http://127.0.0.1:5173 \\");
            println!("    -- --new-window https://superapp.example.com/mini-app/foo");
            println!();
            println!("CA:");
            println!("  rexy trust");
            println!("  rexy clean");
        }
    }

    Ok(())
}

async fn run(args: RunArgs) -> Result<(), Box<dyn std::error::Error>> {
    let rules = resolve_rules(&args)?;

    if rules.is_empty() {
        tracing::warn!("config contains no rules; running without redirects");
    }

    ca::ensure_exists()?;

    let browser = resolve_browser(&args.browser)?;

    if browser.is_firefox() {
        // Firefox uses its own NSS store: `rexy trust --firefox`, not the OS
        // store, so the OS-trust gate does not apply here.
        info!("Firefox browser: make sure the CA is in the profiles (rexy trust --firefox)");
    } else if !trust::is_likely_installed() {
        eprintln!();
        eprintln!("Rexy Local CA is not installed in the OS trust store.");
        eprintln!("Run:");
        eprintln!();
        eprintln!("    rexy trust");
        eprintln!();
        eprintln!("Then run rexy again.");
        eprintln!();
        std::process::exit(1);
    }

    let listener = TcpListener::bind(("127.0.0.1", args.proxy_port)).await?;
    let proxy_addr = listener.local_addr()?;

    // Serve a PAC script that routes only the intercepted hosts through this proxy and
    // lets everything else go DIRECT (otherwise the browser sends all traffic —
    // messenger, WebRTC/STUN, long-poll — through the MITM proxy and its CONNECT
    // passthrough breaks real-time calls).
    let pac_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let pac_addr = pac_listener.local_addr()?;
    let pac_hosts: Vec<String> = rules.iter().map(|rule| rule.host().to_string()).collect();
    let route_all = std::env::var("REXY_PAC_ALL").map(|v| v == "1").unwrap_or(false);
    let pac_content = pac::content(&pac_hosts, proxy_addr.port(), route_all);
    let shared_pac = std::sync::Arc::new(std::sync::RwLock::new(pac_content));
    tokio::spawn(pac::serve(pac_listener, std::sync::Arc::clone(&shared_pac)));

    let pac_url = format!("http://{pac_addr}/proxy.pac");

    let ca = ca::load_ca()?;

    let handler = DevRedirect::new(rules);

    // Hot reload: watch the rules file so edits apply without restarting the
    // proxy or the browser (keeping the browser session alive is the point).
    if let Some(path) = args.file.as_deref() {
        // Detached task: lives until the process exits.
        tokio::spawn(watch_rules_file(
            std::path::PathBuf::from(path),
            handler.rules_handle(),
            std::sync::Arc::clone(&shared_pac),
            proxy_addr.port(),
            route_all,
            std::time::Duration::from_millis(300),
        ));
    }

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

    // Upstream TLS must trust what the OS trusts (keychain), not just the
    // bundled webpki roots — dev targets routinely use internal or mkcert CAs.
    let upstream_tls = hudsucker::rustls::ClientConfig::builder_with_provider(
        hudsucker::rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()?
    .with_native_roots()?
    .with_no_client_auth();

    // HTTP/2 end-to-end: prod pages live on h2 (multiplexing, long-poll),
    // so the upstream connection negotiates h2 via ALPN whenever the target
    // supports it. HTTP/3/QUIC stays off — the browser is launched with
    // --disable-quic.
    let upstream_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(upstream_tls)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(ca)
        .with_http_connector(upstream_connector)
        .with_http_handler(handler.clone())
        .with_graceful_shutdown(async move {
            let _ = stop_rx.await;
        })
        .build()?;

    info!("proxy listening on http://{proxy_addr}");

    for rule in handler.rules() {
        if !rule.intercept() {
            info!(
                "passthrough: https://{}* (intercept = false, CONNECT tunnel only)",
                rule.host()
            );
            continue;
        }

        info!(
            "redirect: https://{}{}* -> {}{}",
            rule.host(),
            rule.path(),
            rule.target(),
            rule.csp_override()
                .map(|csp| format!(" (csp override: {csp:?})"))
                .unwrap_or_default()
        );
    }

    info!("TLS interception is restricted to the configured rule hosts");

    let proxy_task = tokio::spawn(async move {
        if let Err(err) = proxy.start().await {
            error!(?err, "proxy stopped with error");
        }
    });

    let mut child = browser.spawn(&pac_url, &args.browser_args)?;

    info!("browser started");
    info!("press Ctrl+C to stop");

    tokio::select! {
        result = child.wait() => {
            match result {
                Ok(status) => {
                    info!(?status, "browser exited");
                }
                Err(err) => {
                    error!(?err, "failed to wait for browser");
                }
            }
        }

        signal = tokio::signal::ctrl_c() => {
            signal?;

            info!("Ctrl+C received, stopping browser...");

            if let Err(err) = child.kill().await {
                error!(?err, "failed to stop browser");
            }

            let _ = child.wait().await;
        }
    }

    info!("stopping proxy...");

    let _ = stop_tx.send(());
    let _ = proxy_task.await;

    info!("done");

    Ok(())
}

fn resolve_rules(args: &RunArgs) -> Result<Vec<RedirectRule>, Box<dyn std::error::Error>> {
    if let Some(path) = &args.file {
        if args.host.is_some()
            || args.path.is_some()
            || args.target.is_some()
            || args.csp_override.is_some()
        {
            return Err(
                "--file cannot be combined with --host, --path, --target or --csp-override; \
                 configure rules inside the file"
                    .into(),
            );
        }

        return config::load_rules(std::path::Path::new(path));
    }

    let host = args
        .host
        .clone()
        .ok_or("either --file or --host/--target are required")?;
    let target = args
        .target
        .clone()
        .ok_or("either --file or --host/--target are required")?;
    let path = args.path.clone().unwrap_or_else(|| "/".into());
    let csp_override = args
        .csp_override
        .as_deref()
        .map(config::parse_csp_value)
        .transpose()?;

    config::validate_host(&host)?;
    config::validate_path(&path)?;
    config::validate_target(&target)?;

    Ok(vec![RedirectRule::new(host, path, target, csp_override, true, false)])
}

/// `rexy rules check -f <rules.toml> <url>...`: offline rule evaluation using
/// the same matcher as the proxy, for config sanity checks from CI and agent
/// scripts. Unmatched URLs are a normal result (exit code stays 0); an invalid
/// URL or config file is an error.
fn rules_check(
    file: &str,
    json: bool,
    urls: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let rules = config::load_rules(std::path::Path::new(file))?;

    let outcomes: Vec<CheckOutcome> = urls
        .iter()
        .map(|url| rules::check_url(&rules, url))
        .collect::<Result<Vec<_>, String>>()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&outcomes)?);
    } else {
        for outcome in &outcomes {
            print_check_outcome(outcome);
        }
    }

    Ok(())
}

fn print_check_outcome(outcome: &CheckOutcome) {
    if !outcome.matched {
        println!("miss  {} -> no matching rule (passthrough)", outcome.url);
        return;
    }

    let csp = outcome
        .csp_override
        .as_deref()
        .map(|csp| format!(" (csp: {csp})"))
        .unwrap_or_default();

    println!(
        "match {} -> rule #{} (path {}) -> {}{}",
        outcome.url,
        outcome.rule_index.expect("matched outcome has a rule index") + 1,
        outcome.rule_path.as_deref().unwrap_or("/"),
        outcome.target.as_deref().unwrap_or_default(),
        csp
    );
}

/// Watch the rules file and apply changes without a restart: the rule set is
/// swapped behind the shared lock, the PAC is regenerated when the host list
/// changes. A file that fails to load (broken TOML, validation error) keeps
/// the previous rules — the process never dies from a config edit.
///
/// Watching is mtime/size polling (no platform-specific watcher quirks with
/// editors that save via atomic rename); the poll interval keeps the
/// apply latency well under a second.
async fn watch_rules_file(
    path: std::path::PathBuf,
    rules: std::sync::Arc<std::sync::RwLock<Vec<rules::RedirectRule>>>,
    pac_content: std::sync::Arc<std::sync::RwLock<String>>,
    proxy_port: u16,
    route_all: bool,
    interval: std::time::Duration,
) {
    let describe = |rules: &[rules::RedirectRule]| -> String {
        rules
            .iter()
            .map(|rule| format!("{}{} -> {}", rule.host(), rule.path(), rule.target()))
            .collect::<Vec<_>>()
            .join("; ")
    };

    let mut signature = file_signature(&path);

    loop {
        tokio::time::sleep(interval).await;

        let current = file_signature(&path);
        if current == signature {
            continue;
        }
        signature = current;

        match config::load_rules(&path) {
            Ok(new_rules) => {
                let hosts: Vec<String> = new_rules
                    .iter()
                    .map(|rule| rule.host().to_string())
                    .collect();

                *pac_content.write().expect("PAC content lock is poisoned") =
                    pac::content(&hosts, proxy_port, route_all);
                *rules.write().expect("rules lock is poisoned") = new_rules;

                info!("rules file reloaded: {}", describe(&rules.read().expect("rules lock is poisoned")));
            }
            Err(err) => {
                tracing::warn!(
                    %err,
                    "failed to reload rules file; keeping the previous rule set"
                );
            }
        }
    }
}

/// Cheap change signal for the rules file: editors may save via atomic
/// rename, so the identity of the file can change — polling mtime+size of the
/// path catches that as well as in-place writes.
fn file_signature(path: &std::path::Path) -> Option<(std::time::SystemTime, u64)> {
    std::fs::metadata(path)
        .ok()
        .and_then(|meta| {
            let modified = meta.modified().ok()?;
            Some((modified, meta.len()))
        })
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "rexy=info,hudsucker=info".into()),
        )
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> RunArgs {
        RunArgs {
            browser: "chrome".into(),
            file: None,
            host: None,
            path: None,
            target: None,
            proxy_port: 0,
            csp_override: None,
            browser_args: vec![],
        }
    }

    #[test]
    fn file_conflicts_with_single_rule_flags() {
        let mut args = base_args();
        args.file = Some("rules.toml".into());
        args.host = Some("a.example.com".into());

        assert!(resolve_rules(&args).is_err());
    }

    #[test]
    fn single_rule_mode_requires_host_and_target() {
        let args = base_args();
        assert!(resolve_rules(&args).is_err());

        let mut args = base_args();
        args.host = Some("a.example.com".into());
        assert!(resolve_rules(&args).is_err());
    }

    #[test]
    fn single_rule_mode_defaults_path() {
        let mut args = base_args();
        args.host = Some("a.example.com".into());
        args.target = Some("http://127.0.0.1:1111".into());

        let rules = resolve_rules(&args).unwrap();

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].host(), "a.example.com");
        assert_eq!(rules[0].path(), "/");
        assert_eq!(rules[0].target(), "http://127.0.0.1:1111");
    }

    #[test]
    fn single_rule_mode_rejects_invalid_csp() {
        let mut args = base_args();
        args.host = Some("a.example.com".into());
        args.target = Some("http://127.0.0.1:1111".into());
        args.csp_override = Some("bad\nheader".into());

        assert!(resolve_rules(&args).is_err());
    }

    #[tokio::test]
    async fn hot_reload_applies_changed_rules_and_regenerates_pac() {
        let path = std::env::temp_dir().join(format!("rexy-hot-reload-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "[[rules]]\nhost = \"a.example.com\"\ntarget = \"http://127.0.0.1:1111\"\n",
        )
        .unwrap();

        let rules = resolve_rules(&file_mode_args(&path)).unwrap();
        let handler = DevRedirect::new(rules);
        let rules_handle = handler.rules_handle();

        let pac = std::sync::Arc::new(std::sync::RwLock::new(String::new()));
        let pac_handle = std::sync::Arc::clone(&pac);

        let watcher = tokio::spawn(watch_rules_file(
            path.clone(),
            rules_handle.clone(),
            pac_handle,
            8888,
            false,
            std::time::Duration::from_millis(20),
        ));

        // Let the watcher pick up the initial signature first.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        std::fs::write(
            &path,
            "[[rules]]\nhost = \"a.example.com\"\ntarget = \"http://127.0.0.1:1111\"\n\n[[rules]]\nhost = \"b.example.com\"\ntarget = \"http://127.0.0.1:2222\"\n",
        )
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let current = rules_handle.read().unwrap();
        assert_eq!(current.len(), 2);
        assert_eq!(current[1].host(), "b.example.com");
        drop(current);

        // PAC was regenerated with the new host list.
        let pac_now = pac.read().unwrap().clone();
        assert!(pac_now.contains("b.example.com"), "{pac_now}");
        assert!(pac_now.contains("PROXY 127.0.0.1:8888"));

        watcher.abort();
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn hot_reload_keeps_old_rules_on_broken_config() {
        let path =
            std::env::temp_dir().join(format!("rexy-hot-broken-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "[[rules]]\nhost = \"a.example.com\"\ntarget = \"http://127.0.0.1:1111\"\n",
        )
        .unwrap();

        let rules = resolve_rules(&file_mode_args(&path)).unwrap();
        let handler = DevRedirect::new(rules);
        let rules_handle = handler.rules_handle();

        let watcher = tokio::spawn(watch_rules_file(
            path.clone(),
            rules_handle.clone(),
            std::sync::Arc::new(std::sync::RwLock::new(String::new())),
            8888,
            false,
            std::time::Duration::from_millis(20),
        ));

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        // Broken TOML: the previous rule set must survive.
        std::fs::write(&path, "[[rules]]\nhost = ").unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(rules_handle.read().unwrap().len(), 1);

        // A later valid edit still applies (the watcher did not die).
        std::fs::write(
            &path,
            "[[rules]]\nhost = \"c.example.com\"\ntarget = \"http://127.0.0.1:3333\"\n",
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let current = rules_handle.read().unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].host(), "c.example.com");

        watcher.abort();
        std::fs::remove_file(&path).ok();
    }

    fn file_mode_args(path: &std::path::Path) -> RunArgs {
        let mut args = base_args();
        args.file = Some(path.to_string_lossy().into_owned());
        args
    }

    #[test]
    fn file_mode_loads_rules() {
        let path = std::env::temp_dir().join(format!("rexy-cli-test-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "[[rules]]\nhost = \"a.example.com\"\ntarget = \"http://127.0.0.1:1111\"\n\n[[rules]]\nhost = \"b.example.com\"\ntarget = \"http://127.0.0.1:2222\"\n",
        )
        .unwrap();

        let mut args = base_args();
        args.file = Some(path.to_string_lossy().into_owned());

        let rules = resolve_rules(&args).unwrap();

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].host(), "b.example.com");

        std::fs::remove_file(&path).ok();
    }
}
