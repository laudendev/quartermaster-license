use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const PAYLOAD_LEN: usize = 33;
const SIG_LEN: usize = 64;
const RAW_LEN: usize = PAYLOAD_LEN + SIG_LEN; // 97
const CURRENT_VERSION: u8 = 1;

#[derive(Debug, Clone)]
pub struct License {
    pub version: u8,
    pub id: [u8; 16],
    pub product: String,
    pub major_ver: u16,
    pub seats: u16,
    pub issued_at: i64,
}

#[derive(Debug)]
pub enum LicenseError {
    Malformed,
    UnsupportedVersion,
    InvalidSignature,
}

fn normalize(key: &str) -> String {
    key.to_uppercase()
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\n' | '\r' | '\t'))
        .collect()
}

pub fn verify(pub_key: &VerifyingKey, key: &str) -> Result<License, LicenseError> {
    let normalized = normalize(key);
    let raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &normalized)
        .ok_or(LicenseError::Malformed)?;

    if raw.len() != RAW_LEN {
        return Err(LicenseError::Malformed);
    }

    let (payload, sig_bytes) = raw.split_at(PAYLOAD_LEN);

    if payload[0] != CURRENT_VERSION {
        return Err(LicenseError::UnsupportedVersion);
    }

    let signature = Signature::from_slice(sig_bytes).map_err(|_| LicenseError::Malformed)?;
    pub_key
        .verify(payload, &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    let mut id = [0u8; 16];
    id.copy_from_slice(&payload[1..17]);

    let product = String::from_utf8(payload[17..21].to_vec())
        .map_err(|_| LicenseError::Malformed)?;

    let major_ver = u16::from_be_bytes([payload[21], payload[22]]);
    let seats = u16::from_be_bytes([payload[23], payload[24]]);
    let issued_at = i64::from_be_bytes(payload[25..33].try_into().unwrap());

    Ok(License {
        version: payload[0],
        id,
        product,
        major_ver,
        seats,
        issued_at,
    })
}

pub fn verify_any(pubs: &[VerifyingKey], key: &str) -> Result<License, LicenseError> {
    if pubs.is_empty() {
        return Err(LicenseError::Malformed);
    }

    let mut last_err = LicenseError::InvalidSignature;
    for pub_key in pubs {
        match verify(pub_key, key) {
            Ok(license) => return Ok(license),
            Err(e @ LicenseError::Malformed) | Err(e @ LicenseError::UnsupportedVersion) => {
                return Err(e);
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    pub(crate) fn test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    pub(crate) fn issue_test_license(
        signing_key: &SigningKey,
        product: &str,
        major_ver: u16,
        seats: u16,
        issued_at: i64,
    ) -> String {
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = CURRENT_VERSION;
        payload[17..21].copy_from_slice(product.as_bytes());
        payload[21..23].copy_from_slice(&major_ver.to_be_bytes());
        payload[23..25].copy_from_slice(&seats.to_be_bytes());
        payload[25..33].copy_from_slice(&issued_at.to_be_bytes());

        let signature = signing_key.sign(&payload);

        let mut raw = Vec::with_capacity(RAW_LEN);
        raw.extend_from_slice(&payload);
        raw.extend_from_slice(&signature.to_bytes());

        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw)
    }

    #[test]
    fn round_trip() {
        let (signing_key, verifying_key) = test_keypair();
        let key = issue_test_license(&signing_key, "BOOK", 1, 3, 1_700_000_000);

        let license = verify(&verifying_key, &key).expect("should verify");

        assert_eq!(license.product, "BOOK");
        assert_eq!(license.major_ver, 1);
        assert_eq!(license.seats, 3);
        assert_eq!(license.issued_at, 1_700_000_000);
    }

    #[test]
    fn tamper_detection() {
        let (signing_key, verifying_key) = test_keypair();
        let key = issue_test_license(&signing_key, "BOOK", 1, 1, 1_700_000_000);

        let raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &key)
            .expect("valid base32");

        for i in 0..raw.len() {
            let mut tampered = raw.clone();
            tampered[i] ^= 0xFF;
            let tampered_key =
                base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &tampered);

            assert!(
                verify(&verifying_key, &tampered_key).is_err(),
                "tampered byte at position {} was accepted",
                i
            );
        }
    }

    #[test]
    fn unknown_version_rejected() {
        let (signing_key, verifying_key) = test_keypair();
        let key = issue_test_license(&signing_key, "BOOK", 1, 1, 1_700_000_000);

        let mut raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &key)
            .expect("valid base32");
        raw[0] = 2;
        let resigned_payload = &raw[..PAYLOAD_LEN];
        let new_sig = signing_key.sign(resigned_payload);

        let mut tampered = Vec::with_capacity(RAW_LEN);
        tampered.extend_from_slice(resigned_payload);
        tampered.extend_from_slice(&new_sig.to_bytes());
        let tampered_key =
            base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &tampered);

        match verify(&verifying_key, &tampered_key) {
            Err(LicenseError::UnsupportedVersion) => {}
            other => panic!("expected UnsupportedVersion, got {:?}", other),
        }
    }

    #[test]
    fn verify_any_tries_each_key() {
        let (signing_key_1, verifying_key_1) = test_keypair();
        let (_signing_key_2, verifying_key_2) = test_keypair();

        let key = issue_test_license(&signing_key_1, "BOOK", 1, 1, 1_700_000_000);

        let license = verify_any(&[verifying_key_2, verifying_key_1], &key)
            .expect("should verify against the old key");
        assert_eq!(license.product, "BOOK");
    }

    #[test]
    fn verify_any_fails_when_no_key_matches() {
        let (signing_key_1, _verifying_key_1) = test_keypair();
        let (_signing_key_2, verifying_key_2) = test_keypair();

        let key = issue_test_license(&signing_key_1, "BOOK", 1, 1, 1_700_000_000);

        match verify_any(&[verifying_key_2], &key) {
            Err(LicenseError::InvalidSignature) => {}
            other => panic!("expected InvalidSignature, got {:?}", other),
        }
    }
}
