use std::fs;
use std::path::PathBuf;

use hudsucker::{certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs};
use rcgen::{Issuer, KeyPair};

pub fn ca_dir() -> PathBuf {
    PathBuf::from("ca")
}

pub fn cert_path() -> PathBuf {
    ca_dir().join("rexy.cer")
}

pub fn key_path() -> PathBuf {
    ca_dir().join("rexy.key")
}

pub fn ensure_exists() -> Result<(), Box<dyn std::error::Error>> {
    if !cert_path().exists() || !key_path().exists() {
        return Err("CA files are missing. Run ./generate_ca.sh first.".into());
    }

    Ok(())
}

pub fn load_ca() -> Result<RcgenAuthority, Box<dyn std::error::Error>> {
    ensure_exists()?;

    let key_pem = fs::read_to_string(key_path())?;
    let cert_pem = fs::read_to_string(cert_path())?;

    let key_pair = KeyPair::from_pem(&key_pem)?;

    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)?;

    Ok(RcgenAuthority::new(
        issuer,
        1_000,
        aws_lc_rs::default_provider(),
    ))
}
