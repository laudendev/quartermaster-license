use crate::license::{verify_any, License, LicenseError};
use ed25519_dalek::VerifyingKey;
use directories::ProjectDirs;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum StoredLicenseError {
    NoConfigDir,
    IoError(std::io::Error),
    LicenseError(LicenseError),
    PromptFailed,
}

impl From<std::io::Error> for StoredLicenseError {
    fn from(e: std::io::Error) -> Self {
        StoredLicenseError::IoError(e)
    }
}

impl From<LicenseError> for StoredLicenseError {
    fn from(e: LicenseError) -> Self {
        StoredLicenseError::LicenseError(e)
    }
}

fn real_config_dir() -> Result<PathBuf, StoredLicenseError> {
    let dirs = ProjectDirs::from("dev", "lauden", "quartermaster-license")
        .ok_or(StoredLicenseError::NoConfigDir)?;
    Ok(dirs.config_dir().to_path_buf())
}

fn license_file_path_in(
    config_dir: &Path,
    product_code: &str,
) -> Result<PathBuf, StoredLicenseError> {
    fs::create_dir_all(config_dir)?;
    Ok(config_dir.join(format!("{}.key", product_code)))
}

pub fn load_or_prompt_license<F>(
    pubs: &[VerifyingKey],
    product_code: &str,
    prompt: F,
) -> Result<License, StoredLicenseError>
where
    F: FnOnce() -> Option<String>,
{
    let config_dir = real_config_dir()?;
    load_or_prompt_license_in(&config_dir, pubs, product_code, prompt)
}

/// Same behavior as `load_or_prompt_license`, but reads/writes under
/// `config_dir` instead of the real OS config location. Exists so
/// tests can exercise the full logic against a temp directory rather
/// than the caller's real filesystem.
fn load_or_prompt_license_in<F>(
    config_dir: &Path,
    pubs: &[VerifyingKey],
    product_code: &str,
    prompt: F,
) -> Result<License, StoredLicenseError>
where
    F: FnOnce() -> Option<String>,
{
    let path = license_file_path_in(config_dir, product_code)?;

    if let Ok(stored_key) = fs::read_to_string(&path) {
        let stored_key = stored_key.trim();
        if let Ok(license) = verify_any(pubs, stored_key) {
            if license.product == product_code {
                return Ok(license);
            }
        }
    }

    let entered_key = prompt().ok_or(StoredLicenseError::PromptFailed)?;
    let license = verify_any(pubs, &entered_key)?;

    if license.product != product_code {
        return Err(StoredLicenseError::LicenseError(LicenseError::Malformed));
    }

    fs::write(&path, &entered_key)?;
    Ok(license)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::tests::{issue_test_license, test_keypair};

    #[test]
    fn prompts_when_nothing_stored_and_saves_for_next_time() {
        let tmp = std::env::temp_dir().join(format!("qml-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let (signing_key, verifying_key) = test_keypair();
        let key = issue_test_license(&signing_key, "BOOK", 1, 1, 1_700_000_000);

        let mut prompt_calls = 0;
        let license = load_or_prompt_license_in(&tmp, &[verifying_key], "BOOK", || {
            prompt_calls += 1;
            Some(key.clone())
        })
        .expect("should verify and store");

        assert_eq!(license.product, "BOOK");
        assert_eq!(prompt_calls, 1);

        // Second call should load from storage, never prompting again.
        let mut second_prompt_calls = 0;
        let license2 = load_or_prompt_license_in(&tmp, &[verifying_key], "BOOK", || {
            second_prompt_calls += 1;
            None
        })
        .expect("should load from storage without prompting");

        assert_eq!(license2.product, "BOOK");
        assert_eq!(second_prompt_calls, 0);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn rejects_stored_key_for_wrong_product() {
        let tmp = std::env::temp_dir().join(format!("qml-test-wrongproduct-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let (signing_key, verifying_key) = test_keypair();
        // A genuinely valid BOOK license...
        let key = issue_test_license(&signing_key, "BOOK", 1, 1, 1_700_000_000);
        std::fs::write(tmp.join("TOOL.key"), &key).unwrap();

        // ...must not satisfy a binary that expects TOOL.
        let mut prompted = false;
        let result = load_or_prompt_license_in(&tmp, &[verifying_key], "TOOL", || {
            prompted = true;
            None // simulate user cancelling the prompt
        });

        assert!(result.is_err());
        assert!(prompted, "should have fallen through to prompting, not silently accepted the mismatched product");

        std::fs::remove_dir_all(&tmp).ok();
    }
}
