mod browser;
mod ca;
mod config;
mod pac;
mod proxy_handler;
mod trust;

use clap::{Parser, Subcommand};
use hudsucker::{Proxy, rustls::crypto::aws_lc_rs};
use tokio::net::TcpListener;
use tracing::{error, info};

use browser::resolve_browser;
use proxy_handler::{DevRedirect, RedirectRule};

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
    Trust,

    /// Remove the Rexy Local CA from the OS trust store.
    Clean,
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
        Some(Command::Trust) => {
            trust::install()?;
            return Ok(());
        }

        Some(Command::Clean) => {
            trust::remove()?;
            return Ok(());
        }

        Some(Command::Run(args)) => run(args).await?,

        None => {
            println!("Use:");
            println!();
            println!("  rexy run --file <rules.toml>");
            println!("  rexy run --host <host> --path <path> --target <url> -- <browser args>");
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

    if !trust::is_likely_installed() {
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

    let browser = resolve_browser(&args.browser)?;

    let listener = TcpListener::bind(("127.0.0.1", args.proxy_port)).await?;
    let proxy_addr = listener.local_addr()?;

    // Serve a PAC script that routes only the intercepted hosts through this proxy and
    // lets everything else go DIRECT (otherwise the browser sends all traffic —
    // messenger, WebRTC/STUN, long-poll — through the MITM proxy and its CONNECT
    // passthrough breaks real-time calls).
    let pac_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let pac_addr = pac_listener.local_addr()?;
    let pac_hosts: Vec<String> = rules.iter().map(|rule| rule.host().to_string()).collect();
    let pac_content = pac::content(&pac_hosts, proxy_addr.port());
    tokio::spawn(pac::serve(pac_listener, pac_content));

    let pac_url = format!("http://{pac_addr}/proxy.pac");

    let ca = ca::load_ca()?;

    let handler = DevRedirect::new(rules);

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler.clone())
        .with_graceful_shutdown(async move {
            let _ = stop_rx.await;
        })
        .build()?;

    info!("proxy listening on http://{proxy_addr}");

    for rule in handler.rules() {
        info!(
            "redirect: https://{}{}* -> {}",
            rule.host(),
            rule.path(),
            rule.target()
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

    Ok(vec![RedirectRule::new(host, path, target, csp_override)])
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
