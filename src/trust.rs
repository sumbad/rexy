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
fn install_windows(cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
fn install_linux(cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
    Path::new("/usr/local/share/ca-certificates/local-dev-proxy.crt").exists()
}

fn run(program: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new(program).args(args).status()?;

    if !status.success() {
        return Err(format!("{program} exited with status {status}").into());
    }

    Ok(())
}
