use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum FingerprintError {
    MachineIdUnavailable,
}

pub fn fingerprint(product_code: &str) -> Result<String, FingerprintError> {
    let machine_id = read_machine_id()?;

    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(product_code.as_bytes());
    let digest = hasher.finalize();

    Ok(hex::encode(digest))
}

#[cfg(target_os = "linux")]
fn read_machine_id() -> Result<String, FingerprintError> {
    std::fs::read_to_string("/etc/machine-id")
        .map(|s| s.trim().to_string())
        .map_err(|_| FingerprintError::MachineIdUnavailable)
}

#[cfg(target_os = "macos")]
fn read_machine_id() -> Result<String, FingerprintError> {
    let output = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .map_err(|_| FingerprintError::MachineIdUnavailable)?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|l| l.contains("IOPlatformUUID"))
        .and_then(|l| l.split('"').nth(3))
        .map(|s| s.to_string())
        .ok_or(FingerprintError::MachineIdUnavailable)
}

#[cfg(target_os = "windows")]
fn read_machine_id() -> Result<String, FingerprintError> {
    use winreg::enums::*;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Cryptography",
            KEY_READ | KEY_WOW64_64KEY,
        )
        .map_err(|_| FingerprintError::MachineIdUnavailable)?;
    key.get_value("MachineGuid")
        .map_err(|_| FingerprintError::MachineIdUnavailable)
}
