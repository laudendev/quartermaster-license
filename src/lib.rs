pub mod fingerprint;
pub mod license;
pub mod storage;
pub mod trial;

pub use license::{verify, verify_any, License, LicenseError};
pub use storage::{
    load_or_prompt_license, load_stored_license, load_stored_license_in, remove_stored_license_in,
    store_license, store_license_in, StoredLicenseError,
};
pub use trial::{verify_trial, verify_trial_any, Trial, TrialError};

pub mod hardware;
pub mod smbios;
pub mod trial_store;
pub mod trial_v2;
pub mod update;
