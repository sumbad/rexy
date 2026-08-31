mod browser;
mod ca;
mod pac;
mod proxy_handler;
mod trust;

use clap::{Parser, Subcommand};
use hudsucker::{Proxy, rustls::crypto::aws_lc_rs};
use tokio::net::TcpListener;
use tracing::{error, info};

use browser::resolve_browser;
use proxy_handler::{CspOverride, DevRedirect};

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

    /// Production hostname to intercept.
    #[arg(long)]
    host: String,

    /// Production path prefix to redirect.
    #[arg(long, default_value = "/")]
    path: String,

    /// Local development server.
    #[arg(long)]
    target: String,

    /// Local proxy port. 0 means choose a free port.
    #[arg(long, default_value_t = 0)]
    proxy_port: u16,

    /// Override the Content-Security-Policy of responses served from --target.
    /// Pass `off` to remove the header entirely.
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
    validate_host(&args.host)?;
    validate_path(&args.path)?;
    validate_target(&args.target)?;

    let csp_override = parse_csp_override(&args.csp_override)?;

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

    // Serve a PAC script that routes only the intercepted host through this proxy and lets
    // everything else go DIRECT (otherwise the browser sends all traffic — messenger,
    // WebRTC/STUN, long-poll — through the MITM proxy and its CONNECT passthrough breaks
    // real-time calls).
    let pac_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let pac_addr = pac_listener.local_addr()?;
    let pac_content = pac::content(&args.host, proxy_addr.port());
    tokio::spawn(pac::serve(pac_listener, pac_content));

    let pac_url = format!("http://{pac_addr}/proxy.pac");

    let proxy_host = args.host.clone();
    let proxy_path = args.path.clone();
    let local_target = args.target.clone();

    let ca = ca::load_ca()?;

    let handler = DevRedirect::new(
        proxy_host.clone(),
        proxy_path.clone(),
        local_target.clone(),
        csp_override,
    );

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
    info!(
        "redirect: https://{}{}* -> {}",
        proxy_host, proxy_path, local_target
    );
    info!("TLS interception is restricted to host: {}", proxy_host);

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

fn validate_host(host: &str) -> Result<(), Box<dyn std::error::Error>> {
    if host.is_empty() {
        return Err("--host cannot be empty".into());
    }

    if host.contains("://") {
        return Err("--host must contain only hostname, e.g. superapp.example.com".into());
    }

    if host.contains('/') {
        return Err("--host must not contain a path".into());
    }

    Ok(())
}

fn validate_path(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !path.starts_with('/') {
        return Err("--path must start with '/'".into());
    }

    Ok(())
}

fn validate_target(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parsed: hudsucker::hyper::Uri = target.parse()?;

    match parsed.scheme_str() {
        Some("http" | "https") => {}
        _ => {
            return Err("--target must be an http:// or https:// URL".into());
        }
    }

    if parsed.host().is_none() {
        return Err("--target must contain a hostname".into());
    }

    Ok(())
}

fn parse_csp_override(
    raw: &Option<String>,
) -> Result<Option<CspOverride>, Box<dyn std::error::Error>> {
    let Some(raw) = raw else {
        return Ok(None);
    };

    let value = raw.trim();

    if value.is_empty() {
        return Err("--csp-override cannot be empty: pass a policy or 'off'".into());
    }

    if value.eq_ignore_ascii_case("off") {
        return Ok(Some(CspOverride::Off));
    }

    // Rejects newlines and non-visible-ASCII bytes (header injection guard).
    if hudsucker::hyper::header::HeaderValue::from_str(value).is_err() {
        return Err(format!(
            "--csp-override contains characters invalid for an HTTP header: {value:?}"
        )
        .into());
    }

    Ok(Some(CspOverride::Policy(value.to_string())))
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "dev_proxy=info,hudsucker=info".into()),
        )
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_override_none_when_flag_absent() {
        assert_eq!(parse_csp_override(&None).unwrap(), None);
    }

    #[test]
    fn csp_override_parses_off() {
        assert_eq!(
            parse_csp_override(&Some("off".into())).unwrap(),
            Some(CspOverride::Off)
        );
    }

    #[test]
    fn csp_override_parses_policy() {
        assert_eq!(
            parse_csp_override(&Some("frame-ancestors *".into())).unwrap(),
            Some(CspOverride::Policy("frame-ancestors *".into()))
        );
    }

    #[test]
    fn csp_override_rejects_empty() {
        assert!(parse_csp_override(&Some("   ".into())).is_err());
    }

    #[test]
    fn csp_override_rejects_header_injection() {
        assert!(parse_csp_override(&Some("frame-ancestors *\nX-Evil: y".into())).is_err());
    }
}
