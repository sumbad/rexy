use std::fs;

use crate::ca::cert_path;

const CA_NAME: &str = "Rexy Local CA";

pub fn install() -> Result<(), Box<dyn std::error::Error>> {
    let cert = cert_path();

    if !cert.exists() {
        return Err("CA certificate does not exist. Run ./generate_ca.sh first.".into());
    }

    #[cfg(target_os = "macos")]
    install_macos(&cert)?;

    #[cfg(target_os = "windows")]
    install_windows(&cert)?;

    #[cfg(target_os = "linux")]
    install_linux(&cert)?;

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        return Err("automatic CA installation is not supported on this OS".into());
    }

    println!("✓ {CA_NAME} installed");

    Ok(())
}

pub fn remove() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    remove_macos()?;

    #[cfg(target_os = "windows")]
    remove_windows()?;

    #[cfg(target_os = "linux")]
    remove_linux()?;

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        return Err("automatic CA removal is not supported on this OS".into());
    }

    println!("✓ {CA_NAME} removed");

    Ok(())
}

pub fn is_likely_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        return check_macos();
    }

    #[cfg(target_os = "windows")]
    {
        return check_windows();
    }

    #[cfg(target_os = "linux")]
    {
        return check_linux();
    }

    #[allow(unreachable_code)]
    false
}

#[cfg(target_os = "macos")]
fn login_keychain() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let home = std::env::var_os("HOME").ok_or("HOME environment variable is not set")?;

    Ok(std::path::PathBuf::from(home).join("Library/Keychains/login.keychain-db"))
}

#[cfg(target_os = "macos")]
fn install_macos(cert: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let keychain = login_keychain()?;

    // Удаляем старую версию Rexy CA, если она уже была установлена.
    // Это делает `rexy trust` идемпотентным при перевыпуске CA.
    let _ = std::process::Command::new("security")
        .args([
            "delete-certificate",
            "-c",
            CA_NAME,
            keychain.to_string_lossy().as_ref(),
        ])
        .status();

    run(
        "security",
        &[
            "add-trusted-cert",
            "-r",
            "trustRoot",
            "-p",
            "ssl",
            "-k",
            keychain.to_string_lossy().as_ref(),
            cert.to_string_lossy().as_ref(),
        ],
    )?;

    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_macos() -> Result<(), Box<dyn std::error::Error>> {
    let keychain = login_keychain()?;

    let status = std::process::Command::new("security")
        .args([
            "delete-certificate",
            "-c",
            CA_NAME,
            keychain.to_string_lossy().as_ref(),
        ])
        .status()?;

    if !status.success() {
        return Err(format!("failed to remove {CA_NAME} from login keychain").into());
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn check_macos() -> bool {
    let Ok(keychain) = login_keychain() else {
        return false;
    };

    std::process::Command::new("security")
        .args([
            "find-certificate",
            "-a",
            "-c",
            CA_NAME,
            keychain.to_string_lossy().as_ref(),
        ])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn install_windows(cert: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    run(
        "certutil",
        &[
            "-user",
            "-addstore",
            "Root",
            cert.to_string_lossy().as_ref(),
        ],
    )?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn remove_windows() -> Result<(), Box<dyn std::error::Error>> {
    run("certutil", &["-user", "-delstore", "Root", CA_NAME])?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn check_windows() -> bool {
    let result = std::process::Command::new("certutil")
        .args(["-user", "-verifystore", "Root", CA_NAME])
        .status();

    matches!(result, Ok(status) if status.success())
}

#[cfg(target_os = "linux")]
fn install_linux(cert: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new("pkexec")
        .args([
            "cp",
            cert.to_string_lossy().as_ref(),
            "/usr/local/share/ca-certificates/local-dev-proxy.crt",
        ])
        .status()?;

    if !status.success() {
        return Err("failed to copy CA to system trust store".into());
    }

    run("pkexec", &["update-ca-certificates"])?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_linux() -> Result<(), Box<dyn std::error::Error>> {
    run(
        "pkexec",
        &[
            "rm",
            "-f",
            "/usr/local/share/ca-certificates/local-dev-proxy.crt",
        ],
    )?;

    run("pkexec", &["update-ca-certificates"])?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn check_linux() -> bool {
    std::path::Path::new("/usr/local/share/ca-certificates/local-dev-proxy.crt").exists()
}

// ---------- Firefox (NSS) ----------

/// Directory containing Firefox `profiles.ini`, per OS.
fn firefox_profiles_ini() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from)?;

    #[cfg(target_os = "macos")]
    {
        return Some(home.join("Library/Application Support/Firefox/profiles.ini"));
    }

    #[cfg(target_os = "linux")]
    {
        return Some(home.join(".mozilla/firefox/profiles.ini"));
    }

    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var_os("APPDATA").map(std::path::PathBuf::from)?;
        return Some(appdata.join("Mozilla/Firefox/profiles.ini"));
    }

    #[allow(unreachable_code)]
    None
}

/// Extract every `Path=` entry from a `profiles.ini`, resolved against the
/// ini's directory (relative) or taken as-is (absolute). Both `[ProfileN]`
/// and `[Install…]` sections carry a `Path=`.
fn profile_dirs(ini_content: &str, base_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();

    for line in ini_content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        if key.trim() != "Path" {
            continue;
        }

        let value = value.trim();
        let path = std::path::Path::new(value);
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            base_dir.join(value)
        };

        if !dirs.contains(&resolved) {
            dirs.push(resolved);
        }
    }

    dirs
}

fn certutil_hint() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        return "certutil not found — install NSS tools: brew install nss";
    }

    #[cfg(target_os = "linux")]
    {
        return "certutil not found — install NSS tools: sudo apt install libnss3-tools (Debian/Ubuntu)";
    }

    #[cfg(target_os = "windows")]
    {
        return "certutil from NSS not found — install NSS tools (https://wiki.mozilla.org/NSS) and put certutil on PATH";
    }

    #[allow(unreachable_code)]
    "certutil not found — install NSS tools"
}

/// Install the Rexy CA into every Firefox profile via certutil (NSS).
pub fn install_firefox() -> Result<(), Box<dyn std::error::Error>> {
    let ini = firefox_profiles_ini()
        .ok_or("cannot locate the Firefox profiles directory (is Firefox installed?)")?;

    if !ini.exists() {
        return Err(format!(
            "Firefox profiles.ini not found at {} — run Firefox once to create profiles",
            ini.display()
        )
        .into());
    }

    let ini_dir = ini
        .parent()
        .expect("profiles.ini has a parent")
        .to_path_buf();
    let ini_content = fs::read_to_string(&ini)?;
    let dirs = profile_dirs(&ini_content, &ini_dir);

    if dirs.is_empty() {
        return Err("no Firefox profiles found in profiles.ini".into());
    }

    if which_certutil().is_none() {
        return Err(certutil_hint().into());
    }

    let der = ca_der()?;

    let result = install_into_profiles(&dirs, &der);

    // The DER copy in the shared temp dir must not outlive the install:
    // fs::write follows symlinks, so leaving a file at a predictable path
    // is a plant-the-file target. Remove it regardless of the outcome.
    let _ = fs::remove_file(&der);

    result.map(|_| ())
}

/// Ensure the NSS DB exists in `dir` (created with an empty password when
/// the profile has never been used) and import the CA from `der`.
fn import_into_nss_dir(
    dir: &std::path::Path,
    der: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // NSS DB must exist before -A; create it silently when the profile
    // has never been used.
    if !dir.join("cert9.db").exists() {
        run(
            "certutil",
            &[
                "-N",
                "-d",
                &format!("sql:{}", dir.display()),
                "--empty-password",
            ],
        )?;
    }

    run(
        "certutil",
        &[
            "-A",
            "-d",
            &format!("sql:{}", dir.display()),
            "-n",
            CA_NAME,
            "-t",
            "C,,",
            "-i",
            der.to_string_lossy().as_ref(),
        ],
    )
}

/// Import the CA into every existing profile directory; returns the number
/// of profiles modified via `installed`.
fn install_into_profiles(
    dirs: &[std::path::PathBuf],
    der: &std::path::Path,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut installed = 0usize;
    for dir in dirs {
        if !dir.exists() {
            tracing::warn!(profile = %dir.display(), "profile directory missing, skipping");
            continue;
        }

        import_into_nss_dir(dir, der)?;

        println!(
            "✓ {CA_NAME} installed into Firefox profile {}",
            dir.display()
        );
        installed += 1;
    }

    if installed == 0 {
        return Err("no Firefox profile was modified".into());
    }

    Ok(installed)
}

/// Import the local CA into one NSS profile directory — used for real
/// Firefox profiles (`trust --firefox`) and for the throwaway proxy profile
/// spawned by `--browser firefox` (browser.rs). Fails with the certutil
/// install hint when the NSS tools are not on PATH.
pub(crate) fn import_ca_into_nss_profile(
    dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if which_certutil().is_none() {
        return Err(certutil_hint().into());
    }

    let der = ca_der()?;
    let result = import_into_nss_dir(dir, &der);
    // The temp DER copy must not outlive the import (see ca_der).
    let _ = fs::remove_file(&der);
    result
}

/// Remove the Rexy CA from every Firefox profile (ignore "not found").
pub fn remove_firefox() -> Result<(), Box<dyn std::error::Error>> {
    let ini = firefox_profiles_ini()
        .ok_or("cannot locate the Firefox profiles directory (is Firefox installed?)")?;

    if !ini.exists() {
        return Err(format!("Firefox profiles.ini not found at {}", ini.display()).into());
    }

    if which_certutil().is_none() {
        return Err(certutil_hint().into());
    }

    let ini_dir = ini
        .parent()
        .expect("profiles.ini has a parent")
        .to_path_buf();
    let dirs = profile_dirs(&fs::read_to_string(&ini)?, &ini_dir);

    for dir in dirs {
        // -D fails when the nickname is absent — that is the expected state
        // for profiles never touched by rexy, so ignore the exit status.
        let _ = std::process::Command::new("certutil")
            .args(["-D", "-d", &format!("sql:{}", dir.display()), "-n", CA_NAME])
            .status();
    }

    println!("✓ {CA_NAME} removed from Firefox profiles");

    Ok(())
}

fn which_certutil() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("certutil"))
        .find(|candidate| candidate.is_file())
}

/// DER bytes of the local CA: certutil -A expects DER, while `ca/rexy.cer`
/// is PEM — strip the armor and base64-decode. The caller must remove the
/// temp file when done (see `install_firefox`).
fn ca_der() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use base64::Engine;

    let pem = fs::read_to_string(cert_path())?;
    let body: String = pem
        .lines()
        .filter(|line| !line.contains("-----"))
        .collect::<Vec<_>>()
        .join("");

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|err| format!("CA certificate is not valid PEM: {err}"))?;

    // Predictable temp paths are a symlink-planting target (fs::write
    // follows symlinks): the nanosecond component keeps a second call in
    // the same process — or a pid collision — from reusing the path.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("rexy-ca-{}-{nanos}.der", std::process::id()));
    fs::write(&tmp, decoded)?;

    Ok(tmp)
}

fn run(program: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new(program).args(args).status()?;

    if !status.success() {
        return Err(format!("{program} exited with status {status}").into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_ini_paths_are_resolved_and_deduped() {
        let ini = r#"[Install4F96D1932A9F858E]
Default=Profiles/xyz.install
Locked=1

[Profile1]
Name=default
IsRelative=1
Path=Profiles/abc.default

[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/abc.default-release

[Profile2]
Name=work
IsRelative=0
Path=/Users/me/FirefoxProfiles/work
"#;

        let base = std::path::Path::new("/base");
        let dirs = profile_dirs(ini, base);

        // Only `Path=` keys count: the `[Install…]` section's `Default=` is
        // not a profile path entry (the profile has its own [ProfileN]).
        assert_eq!(
            dirs,
            vec![
                std::path::PathBuf::from("/base/Profiles/abc.default"),
                std::path::PathBuf::from("/base/Profiles/abc.default-release"),
                std::path::PathBuf::from("/Users/me/FirefoxProfiles/work"),
            ]
        );
    }

    #[test]
    fn firefox_prefs_point_at_pac_and_disable_http3() {
        let user_js = crate::browser::firefox_user_js("http://127.0.0.1:59999/proxy.pac");

        assert!(user_js.contains("user_pref(\"network.proxy.type\", 2);"));
        assert!(user_js.contains(
            "user_pref(\"network.proxy.autoconfig_url\", \"http://127.0.0.1:59999/proxy.pac\");"
        ));
        assert!(user_js.contains("user_pref(\"network.http.http3.enable\", false);"));
    }
}
