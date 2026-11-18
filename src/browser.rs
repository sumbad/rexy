use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::{Child, Command};

/// Browser family: Chromium browsers take proxy settings on the command
/// line, Firefox needs a temporary profile with proxy prefs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Chromium,
    Firefox,
}

#[derive(Debug, Clone)]
pub struct Browser {
    executable: PathBuf,
    kind: Kind,
}

pub fn resolve_browser(value: &str) -> Result<Browser, Box<dyn std::error::Error>> {
    let (executable, kind) = match value {
        "chrome" => (find_chrome()?, Kind::Chromium),
        "chromium" => (find_chromium()?, Kind::Chromium),
        "firefox" => (find_firefox()?, Kind::Firefox),
        path => {
            let path = PathBuf::from(path);

            if !path.exists() {
                return Err(
                    format!("browser executable does not exist: {}", path.display()).into(),
                );
            }

            // A custom path is Firefox when its file name says so (an
            // Electron/Chromium executable keeps the Chromium command line).
            let kind = if path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.to_ascii_lowercase().contains("firefox"))
                .unwrap_or(false)
            {
                Kind::Firefox
            } else {
                Kind::Chromium
            };

            (path, kind)
        }
    };

    Ok(Browser { executable, kind })
}

impl Browser {
    pub fn is_firefox(&self) -> bool {
        self.kind == Kind::Firefox
    }

    pub fn spawn(
        &self,
        pac_url: &str,
        browser_args: &[String],
    ) -> Result<Child, Box<dyn std::error::Error>> {
        tracing::info!(
            executable = %self.executable.display(),
            pac_url = %pac_url,
            "starting browser"
        );

        match self.kind {
            Kind::Chromium => self.spawn_chromium(pac_url, browser_args),
            Kind::Firefox => self.spawn_firefox(pac_url, browser_args),
        }
    }

    fn spawn_chromium(
        &self,
        pac_url: &str,
        browser_args: &[String],
    ) -> Result<Child, Box<dyn std::error::Error>> {
        if !isolates_profile(browser_args) {
            // WHY no throwaway profile by default: rexy deliberately drives
            // the user's live sessions (prod accounts included) — an
            // isolated profile would defeat that. The handoff risk is
            // reported instead of silently worked around.
            tracing::warn!(
                "Chrome may hand off to an already-running instance and ignore the proxy flags; \
                 pass an isolated profile after `--` to be safe: \
                 -- --user-data-dir=/tmp/rexy-chrome-profile"
            );
        }

        let mut command = Command::new(&self.executable);

        command
            .arg(format!("--proxy-pac-url={pac_url}"))
            .arg("--disable-quic")
            .args(browser_args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        Ok(command.spawn()?)
    }

    /// Firefox has no proxy command-line flags: a throwaway profile with
    /// proxy prefs is created instead. QUIC/HTTP3 is disabled by pref, the
    /// same way Chromium gets `--disable-quic`.
    fn spawn_firefox(
        &self,
        pac_url: &str,
        browser_args: &[String],
    ) -> Result<Child, Box<dyn std::error::Error>> {
        let profile = create_firefox_profile_dir()?;

        std::fs::write(profile.join("user.js"), firefox_user_js(pac_url))?;

        // Firefox does not read the OS trust store: without the CA in this
        // profile, interception fails with certificate errors on Linux /
        // older versions / enterprise policies even after `rexy trust`.
        // Best effort — a missing certutil must not stop the launch.
        match crate::trust::import_ca_into_nss_profile(&profile) {
            Ok(()) => tracing::info!(
                profile = %profile.display(),
                "CA imported into the throwaway Firefox profile"
            ),
            Err(err) => tracing::warn!(
                %err,
                profile = %profile.display(),
                "CA was not installed into the Firefox profile; sites may fail with \
                 certificate errors — install NSS certutil (rexy trust --firefox uses it too)"
            ),
        }

        let mut command = Command::new(&self.executable);

        command
            .arg("--profile")
            .arg(&profile)
            .arg("-no-remote")
            .args(browser_args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        Ok(command.spawn()?)
    }
}

/// Whether the browser args pin an isolated profile (`--user-data-dir`):
/// without one, Chromium hands the command line off to an already-running
/// instance and the proxy flags are silently ignored.
fn isolates_profile(browser_args: &[String]) -> bool {
    browser_args.iter().any(|arg| arg.contains("user-data-dir"))
}

/// Temp directory name of the throwaway Firefox profile for `nanos`/`attempt`.
fn firefox_profile_name(nanos: u32, attempt: u32) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rexy-firefox-profile-{}-{}-{}",
        std::process::id(),
        nanos,
        attempt
    ))
}

/// Create the throwaway Firefox profile directory. Exclusive create over a
/// pid+nanosecond+attempt name: certutil follows symlinks when it writes
/// cert9.db into the directory, so an existing (possibly planted) path must
/// never be reused — `create_dir_all` would silently accept it.
fn create_firefox_profile_dir() -> std::io::Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);

    create_firefox_profile_dir_at(nanos)
}

fn create_firefox_profile_dir_at(nanos: u32) -> std::io::Result<PathBuf> {
    for attempt in 0..4u32 {
        let dir = firefox_profile_name(nanos, attempt);

        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(std::io::Error::other(
        "could not create a unique Firefox profile directory",
    ))
}

/// prefs.js content for the throwaway Firefox profile.
pub(crate) fn firefox_user_js(pac_url: &str) -> String {
    format!(
        r#"// Generated by rexy — throwaway profile for this session.
user_pref("network.proxy.type", 2);
user_pref("network.proxy.autoconfig_url", "{pac_url}");
user_pref("network.http.http3.enable", false);
"#
    )
}

fn find_firefox() -> Result<PathBuf, Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    {
        let candidate = "/Applications/Firefox.app/Contents/MacOS/firefox";
        if Path::new(candidate).exists() {
            return Ok(PathBuf::from(candidate));
        }
    }

    #[cfg(target_os = "windows")]
    {
        let candidates = [
            std::env::var("PROGRAMFILES")
                .ok()
                .map(|v| PathBuf::from(v).join("Mozilla Firefox/firefox.exe")),
            std::env::var("PROGRAMFILES(X86)")
                .ok()
                .map(|v| PathBuf::from(v).join("Mozilla Firefox/firefox.exe")),
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
            "/usr/bin/firefox",
            "/usr/bin/firefox-esr",
            "/snap/bin/firefox",
        ] {
            if Path::new(candidate).exists() {
                return Ok(PathBuf::from(candidate));
            }
        }
    }

    Err("Firefox was not found; pass --browser /path/to/firefox".into())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_data_dir_in_any_form_isolates_the_session() {
        let flag_value = vec!["--user-data-dir=/tmp/rexy-chrome".to_string()];
        assert!(isolates_profile(&flag_value));

        let flag_separate = vec![
            "--user-data-dir".to_string(),
            "/tmp/rexy-chrome".to_string(),
        ];
        assert!(isolates_profile(&flag_separate));

        let unrelated: Vec<String> = vec![
            "--new-window".to_string(),
            "https://example.com/".to_string(),
        ];
        assert!(!isolates_profile(&unrelated));
        assert!(!isolates_profile(&[]));
    }

    #[test]
    fn firefox_profile_dir_name_is_not_bare_pid() {
        // certutil follows symlinks into the profile directory: a
        // pid-only name would be a predictable plant-the-DB target.
        let name = firefox_profile_name(754708000, 0)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("profile dir has a file name")
            .to_owned();
        let bare = format!("rexy-firefox-profile-{}", std::process::id());

        assert!(name.starts_with(&bare), "{name}");
        assert!(
            name.len() > bare.len(),
            "profile dir must carry a uniqueness suffix: {name}"
        );
    }

    #[test]
    fn firefox_profile_creation_never_reuses_an_existing_dir() {
        // Plant the directory the first attempt would produce: the exclusive
        // create must move on to another name instead of reusing it
        // (create_dir_all would silently accept the planted path).
        let nanos = 42;
        let planted = firefox_profile_name(nanos, 0);
        std::fs::create_dir_all(&planted).unwrap();

        let created = create_firefox_profile_dir_at(nanos).expect("a free name is found");

        assert_ne!(created, planted, "a planted dir must not be reused");
        assert!(created.is_dir(), "the created profile dir must exist");
        assert!(planted.is_dir(), "the planted dir must stay untouched");

        std::fs::remove_dir_all(&planted).ok();
        std::fs::remove_dir_all(&created).ok();
    }
}
