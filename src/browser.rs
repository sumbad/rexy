use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::{Child, Command};

#[derive(Debug, Clone)]
pub struct Browser {
    executable: PathBuf,
}

pub fn resolve_browser(value: &str) -> Result<Browser, Box<dyn std::error::Error>> {
    let executable = match value {
        "chrome" => find_chrome()?,
        "chromium" => find_chromium()?,
        path => {
            let path = PathBuf::from(path);

            if !path.exists() {
                return Err(
                    format!("browser executable does not exist: {}", path.display()).into(),
                );
            }

            path
        }
    };

    Ok(Browser { executable })
}

impl Browser {
    pub fn spawn(
        &self,
        pac_url: &str,
        browser_args: &[String],
    ) -> Result<Child, Box<dyn std::error::Error>> {
        let mut command = Command::new(&self.executable);

        command
            .arg(format!("--proxy-pac-url={pac_url}"))
            .arg("--disable-quic")
            .args(browser_args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        tracing::info!(
            executable = %self.executable.display(),
            pac_url = %pac_url,
            "starting browser"
        );

        let child = command.spawn()?;

        Ok(child)
    }
}

fn find_chrome() -> Result<PathBuf, Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    {
        let candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
        ];

        for candidate in candidates {
            if Path::new(candidate).exists() {
                return Ok(PathBuf::from(candidate));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let candidates = [
            std::env::var("PROGRAMFILES")
                .ok()
                .map(|v| PathBuf::from(v).join("Google/Chrome/Application/chrome.exe")),
            std::env::var("PROGRAMFILES(X86)")
                .ok()
                .map(|v| PathBuf::from(v).join("Google/Chrome/Application/chrome.exe")),
            std::env::var("LOCALAPPDATA")
                .ok()
                .map(|v| PathBuf::from(v).join("Google/Chrome/Application/chrome.exe")),
        ];

        for candidate in candidates.into_iter().flatten() {
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        for candidate in [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
        ] {
            if Path::new(candidate).exists() {
                return Ok(PathBuf::from(candidate));
            }
        }
    }

    Err("Google Chrome was not found; pass --browser /path/to/chrome".into())
}

fn find_chromium() -> Result<PathBuf, Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    {
        let candidates = ["/Applications/Chromium.app/Contents/MacOS/Chromium"];

        for candidate in candidates {
            if Path::new(candidate).exists() {
                return Ok(PathBuf::from(candidate));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let candidates = [std::env::var("LOCALAPPDATA")
            .ok()
            .map(|v| PathBuf::from(v).join("Chromium/Application/chrome.exe"))];

        for candidate in candidates.into_iter().flatten() {
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        for candidate in ["/usr/bin/chromium", "/usr/bin/chromium-browser"] {
            if Path::new(candidate).exists() {
                return Ok(PathBuf::from(candidate));
            }
        }
    }

    Err("Chromium was not found; pass --browser /path/to/chromium".into())
}
