//! Signs and checks the release list that Pop Focus's updater trusts.
//!
//! The release key lives on a hardware token, so signing is split: `message`
//! writes the exact bytes to sign, any external signer signs them, and `attach`
//! checks that raw 64-byte signature against the public key before writing it in
//! the form the updater reads. `keygen` and `sign` use a key in a file and are for
//! tests only.
//!
//! Run: cargo run --example update_sign -- <command> ...

use std::fs;
use std::io::Write;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use quartermaster_license::update::{self, signing_message};

/// Must match `ALLOWED_HOSTS` in the app (`popfocus::updater`).
const ALLOWED_HOSTS: &[&str] = &["popfocus.lauden.dev"];

const USAGE: &str = "\
usage:
  update_sign keygen <key-file>                       software key, tests only
  update_sign pubkey <key-file>                       print the public key as hex
  update_sign message <manifest> <out>                write the exact bytes to sign
  update_sign sign <manifest> <key-file> <out-sig>    sign with a software key
  update_sign attach <manifest> <raw-sig> <pubkey-hex> <out-sig>
                                                      check a raw 64-byte signature made
                                                      elsewhere and write it in release form
  update_sign check <product> <manifest> <sig-file> <pubkey-hex>...
                                                      verify the way the app does";

type Outcome = Result<(), String>;

fn read(path: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn write(path: &str, bytes: &[u8]) -> Outcome {
    fs::write(path, bytes).map_err(|e| format!("cannot write {path}: {e}"))
}

fn hex32(text: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(text.trim()).map_err(|_| "not hex".to_string())?;
    <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| "expected 32 bytes (64 hex digits)".to_string())
}

fn read_key(path: &str) -> Result<SigningKey, String> {
    let text = String::from_utf8(read(path)?).map_err(|_| "the key file is not text")?;
    Ok(SigningKey::from_bytes(&hex32(&text)?))
}

fn parse_pubkey(text: &str) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(&hex32(text)?)
        .map_err(|_| "not a valid Ed25519 public key".to_string())
}

fn encode(sig: &Signature) -> String {
    format!(
        "{}\n",
        base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            &sig.to_bytes()
        )
    )
}

fn write_new_secret(path: &str, text: &str) -> Outcome {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create {path}: {e}"))?;
    file.write_all(text.as_bytes()).map_err(|e| e.to_string())
}

fn keygen(path: &str) -> Outcome {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    write_new_secret(path, &format!("{}\n", hex::encode(key.to_bytes())))?;
    println!("{}", hex::encode(key.verifying_key().to_bytes()));
    eprintln!("wrote {path}, owner-only. A key in a file is for tests; the release key lives on the token.");
    Ok(())
}

fn pubkey_command(path: &str) -> Outcome {
    println!(
        "{}",
        hex::encode(read_key(path)?.verifying_key().to_bytes())
    );
    Ok(())
}

fn message(manifest: &str, out: &str) -> Outcome {
    write(out, &signing_message(&read(manifest)?))
}

fn sign(manifest: &str, key: &str, out: &str) -> Outcome {
    let sig = read_key(key)?.sign(&signing_message(&read(manifest)?));
    write(out, encode(&sig).as_bytes())
}

fn attach(manifest: &str, raw: &str, pubkey: &str, out: &str) -> Outcome {
    let json = read(manifest)?;
    let bytes = read(raw)?;
    let sig = Signature::from_slice(&bytes).map_err(|_| {
        format!(
            "{raw} is not a 64-byte Ed25519 signature (it has {} bytes)",
            bytes.len()
        )
    })?;
    parse_pubkey(pubkey)?
        .verify(&signing_message(&json), &sig)
        .map_err(|_| "the signature does not match this manifest and public key".to_string())?;
    write(out, encode(&sig).as_bytes())
}

fn check(product: &str, manifest: &str, sig: &str, keys: &[&str]) -> Outcome {
    let json = read(manifest)?;
    let signature = String::from_utf8(read(sig)?).map_err(|_| "the signature is not text")?;
    let keys = keys
        .iter()
        .map(|k| parse_pubkey(k))
        .collect::<Result<Vec<_>, _>>()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;
    let m = update::verify_manifest(&keys, product, &json, &signature, now, ALLOWED_HOSTS)
        .map_err(|e| format!("rejected: {e}"))?;
    println!(
        "ok: {} versions, floor {}, latest {}, expires_at {}",
        m.versions.len(),
        m.floor,
        m.latest,
        m.expires_at
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match words.as_slice() {
        ["keygen", key] => keygen(key),
        ["pubkey", key] => pubkey_command(key),
        ["message", manifest, out] => message(manifest, out),
        ["sign", manifest, key, out] => sign(manifest, key, out),
        ["attach", manifest, raw, pubkey, out] => attach(manifest, raw, pubkey, out),
        ["check", product, manifest, sig, keys @ ..] if !keys.is_empty() => {
            check(product, manifest, sig, keys)
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(64);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
