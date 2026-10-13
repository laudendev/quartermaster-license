use crate::license::{verify_any, License, LicenseError};
use directories::ProjectDirs;
use ed25519_dalek::VerifyingKey;
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

/// Loads the stored, verified license for `product_code` without
/// prompting and without creating anything on disk. Returns `Ok(None)` when
/// no file exists, or when the stored key no longer verifies or belongs to a
/// different product.
pub fn load_stored_license(
    pubs: &[VerifyingKey],
    product_code: &str,
) -> Result<Option<(License, String)>, StoredLicenseError> {
    let config_dir = real_config_dir()?;
    load_stored_license_in(&config_dir, pubs, product_code)
}

/// Like [`load_stored_license`], but reads from `config_dir` instead of the
/// shared Quartermaster directory. For products that keep their own state.
pub fn load_stored_license_in(
    config_dir: &Path,
    pubs: &[VerifyingKey],
    product_code: &str,
) -> Result<Option<(License, String)>, StoredLicenseError> {
    let path = config_dir.join(format!("{}.key", product_code));
    let stored_key = match fs::read_to_string(&path) {
        Ok(s) => s.trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    match verify_any(pubs, &stored_key) {
        Ok(license) if license.product == product_code => Ok(Some((license, stored_key))),
        _ => Ok(None),
    }
}

/// Verifies `key` and, if it is valid for `product_code`, stores it where
/// every Quartermaster-licensed program on this machine looks for it. The
/// write is atomic (temp file + rename) and the file is created with mode
/// 0600 on Unix, because the key doubles as a bearer credential for download
/// requests.
pub fn store_license(
    pubs: &[VerifyingKey],
    product_code: &str,
    key: &str,
) -> Result<License, StoredLicenseError> {
    let config_dir = real_config_dir()?;
    store_license_in(&config_dir, pubs, product_code, key)
}

/// Like [`store_license`], but writes into `config_dir`.
pub fn store_license_in(
    config_dir: &Path,
    pubs: &[VerifyingKey],
    product_code: &str,
    key: &str,
) -> Result<License, StoredLicenseError> {
    let key = key.trim();
    let license = verify_any(pubs, key)?;
    if license.product != product_code {
        return Err(StoredLicenseError::LicenseError(LicenseError::Malformed));
    }
    let path = license_file_path_in(config_dir, product_code)?;
    let tmp = path.with_extension("key.tmp");
    write_private(&tmp, key.as_bytes())?;
    fs::rename(&tmp, &path)?;
    Ok(license)
}

/// Deletes the stored key for `product_code` from `config_dir`. A missing
/// file is not an error.
pub fn remove_stored_license_in(
    config_dir: &Path,
    product_code: &str,
) -> Result<(), StoredLicenseError> {
    match fs::remove_file(config_dir.join(format!("{}.key", product_code))) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = fs::remove_file(path);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

/// Loads a previously-stored, verified license for `product_code`, or
/// if none exists, calls `prompt` to obtain one, verifies it, and
/// stores it for next time. Identical behavior whether called by a
/// launcher on first run or a standalone product binary that has
/// never seen a launcher — the only shared state is this file.
///
/// Returns both the parsed `License` and the raw key string it was
/// verified from — callers that need to make further authenticated
/// requests (e.g. a launcher calling a download endpoint) need the
/// raw string, not just the parsed fields.
pub fn load_or_prompt_license<F>(
    pubs: &[VerifyingKey],
    product_code: &str,
    prompt: F,
) -> Result<(License, String), StoredLicenseError>
where
    F: FnOnce() -> Option<String>,
{
    let config_dir = real_config_dir()?;
    load_or_prompt_license_in(&config_dir, pubs, product_code, prompt)
}

fn load_or_prompt_license_in<F>(
    config_dir: &Path,
    pubs: &[VerifyingKey],
    product_code: &str,
    prompt: F,
) -> Result<(License, String), StoredLicenseError>
where
    F: FnOnce() -> Option<String>,
{
    if let Some(found) = load_stored_license_in(config_dir, pubs, product_code)? {
        return Ok(found);
    }
    let entered_key = prompt().ok_or(StoredLicenseError::PromptFailed)?;
    let license = store_license_in(config_dir, pubs, product_code, &entered_key)?;
    Ok((license, entered_key.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::tests::{issue_test_license, test_keypair};

    fn fresh_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qml-test-{}-{}", tag, std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        d
    }

    #[test]
    fn load_stored_is_none_and_creates_nothing_when_absent() {
        let dir = fresh_dir("absent");
        let (_s, v) = test_keypair();
        assert!(load_stored_license_in(&dir, &[v], "BOOK")
            .unwrap()
            .is_none());
        assert!(!dir.exists());
    }

    #[test]
    fn store_then_load_round_trips() {
        let dir = fresh_dir("store");
        let (sk, v) = test_keypair();
        let key = issue_test_license(&sk, "BOOK", 1, 1, 1_700_000_000);
        let lic = store_license_in(&dir, &[v], "BOOK", &format!("  {}\n", key)).unwrap();
        assert_eq!(lic.major_ver, 1);
        let (lic2, raw) = load_stored_license_in(&dir, &[v], "BOOK").unwrap().unwrap();
        assert_eq!(lic2.product, "BOOK");
        assert_eq!(raw, key);
        assert!(!dir.join("BOOK.key.tmp").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn store_rejects_other_product_and_bad_signature() {
        let dir = fresh_dir("reject");
        let (sk, v) = test_keypair();
        let (sk2, _v2) = test_keypair();
        let other = issue_test_license(&sk, "TOOL", 1, 1, 1);
        assert!(store_license_in(&dir, &[v], "BOOK", &other).is_err());
        let forged = issue_test_license(&sk2, "BOOK", 1, 1, 1);
        assert!(store_license_in(&dir, &[v], "BOOK", &forged).is_err());
        assert!(!dir.join("BOOK.key").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn invalid_stored_key_loads_as_none() {
        let dir = fresh_dir("invalid");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("BOOK.key"), "garbage").unwrap();
        let (_s, v) = test_keypair();
        assert!(load_stored_license_in(&dir, &[v], "BOOK")
            .unwrap()
            .is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_deletes_the_key_and_tolerates_absence() {
        let dir = fresh_dir("remove");
        let (sk, v) = test_keypair();
        let key = issue_test_license(&sk, "BOOK", 1, 1, 1);
        store_license_in(&dir, &[v], "BOOK", &key).unwrap();
        assert!(dir.join("BOOK.key").exists());
        remove_stored_license_in(&dir, "BOOK").unwrap();
        assert!(!dir.join("BOOK.key").exists());
        assert!(load_stored_license_in(&dir, &[v], "BOOK")
            .unwrap()
            .is_none());
        remove_stored_license_in(&dir, "BOOK").unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn stored_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_dir("perm");
        let (sk, v) = test_keypair();
        let key = issue_test_license(&sk, "BOOK", 1, 1, 1);
        store_license_in(&dir, &[v], "BOOK", &key).unwrap();
        let mode = std::fs::metadata(dir.join("BOOK.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prompts_when_nothing_stored_and_saves_for_next_time() {
        let tmp = std::env::temp_dir().join(format!("qml-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let (signing_key, verifying_key) = test_keypair();
        let key = issue_test_license(&signing_key, "BOOK", 1, 1, 1_700_000_000);

        let mut prompt_calls = 0;
        let (license, returned_key) =
            load_or_prompt_license_in(&tmp, &[verifying_key], "BOOK", || {
                prompt_calls += 1;
                Some(key.clone())
            })
            .expect("should verify and store");

        assert_eq!(license.product, "BOOK");
        assert_eq!(returned_key, key);
        assert_eq!(prompt_calls, 1);

        let mut second_prompt_calls = 0;
        let (license2, returned_key2) =
            load_or_prompt_license_in(&tmp, &[verifying_key], "BOOK", || {
                second_prompt_calls += 1;
                None
            })
            .expect("should load from storage without prompting");

        assert_eq!(license2.product, "BOOK");
        assert_eq!(returned_key2, key);
        assert_eq!(second_prompt_calls, 0);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn rejects_stored_key_for_wrong_product() {
        let tmp =
            std::env::temp_dir().join(format!("qml-test-wrongproduct-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let (signing_key, verifying_key) = test_keypair();
        let key = issue_test_license(&signing_key, "BOOK", 1, 1, 1_700_000_000);
        std::fs::write(tmp.join("TOOL.key"), &key).unwrap();

        let mut prompted = false;
        let result = load_or_prompt_license_in(&tmp, &[verifying_key], "TOOL", || {
            prompted = true;
            None
        });

        assert!(result.is_err());
        assert!(
            prompted,
            "should have fallen through to prompting, not silently accepted the mismatched product"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }
}
