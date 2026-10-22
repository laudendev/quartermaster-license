//! Hardware signals that tell computers apart for the free trial.
//!
//! A computer is described by a few independent hardware identifiers, each
//! hashed on its own as `SHA-256(product "|" kind "|" value)`; the raw values
//! never leave the machine. Quartermaster treats two requests as the same
//! computer when they share at least one signal, so a reinstall (same
//! hardware) or one replaced part keeps the same trial, while two computers
//! made from one disk image (same operating-system IDs, different hardware)
//! do not.
//!
//! Where the identifiers come from, none of them needing administrator rights:
//!
//! - Windows: the SMBIOS table via `GetSystemFirmwareTable('RSMB')`: system
//!   UUID (`uuid`), system serial (`serial`), baseboard serial (`board`).
//! - macOS: `IOPlatformUUID` (`uuid`) and `IOPlatformSerialNumber` (`serial`).
//! - Linux: disk identifiers from `/dev/disk/by-id` (`disk`, at most three
//!   internal disks), plus the DMI product UUID (`uuid`) when the system lets
//!   an ordinary user read it.
//! - Only when none of those can be read: the operating system's own machine
//!   ID (`os`). It changes on reinstall, so such a computer cannot keep its
//!   trial across one.

use sha2::{Digest, Sha256};

use crate::smbios::HardwareIds;

/// Most disks used as signals.
const MAX_DISKS: usize = 3;

/// One hashed hardware identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    /// `uuid`, `serial`, `board`, `disk` or `os`; sent to Quartermaster.
    pub kind: &'static str,
    pub hash: [u8; 32],
}

impl Signal {
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

/// Identifiers as read from the computer, before hashing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawIds {
    pub uuid: Option<Vec<u8>>,
    pub serial: Option<String>,
    pub board: Option<String>,
    pub disks: Vec<String>,
    pub os: Option<String>,
}

/// `SHA-256(product "|" kind "|" value)`.
pub fn signal_hash(product: &str, kind: &str, value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(product.as_bytes());
    hasher.update(b"|");
    hasher.update(kind.as_bytes());
    hasher.update(b"|");
    hasher.update(value);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// The signals for `raw`: every hardware identifier present, or just the
/// operating-system fallback when there is none. Never repeats a hash.
pub fn signals_from(product: &str, raw: &RawIds) -> Vec<Signal> {
    fn push(out: &mut Vec<Signal>, product: &str, kind: &'static str, value: &[u8]) {
        let hash = signal_hash(product, kind, value);
        if !out.iter().any(|s| s.hash == hash) {
            out.push(Signal { kind, hash });
        }
    }
    let mut out: Vec<Signal> = Vec::new();
    if let Some(uuid) = &raw.uuid {
        push(&mut out, product, "uuid", uuid);
    }
    if let Some(serial) = &raw.serial {
        push(&mut out, product, "serial", serial.as_bytes());
    }
    if let Some(board) = &raw.board {
        push(&mut out, product, "board", board.as_bytes());
    }
    for disk in raw.disks.iter().take(MAX_DISKS) {
        push(&mut out, product, "disk", disk.as_bytes());
    }
    if out.is_empty() {
        if let Some(os) = &raw.os {
            push(&mut out, product, "os", os.as_bytes());
        }
    }
    out
}

/// The hashes alone, for comparing with a stored trial.
pub fn hashes(signals: &[Signal]) -> Vec<[u8; 32]> {
    signals.iter().map(|s| s.hash).collect()
}

// ---- SMBIOS (Windows, and any platform that can hand over the raw table) ----

/// Maps parsed SMBIOS values to raw ids (placeholders already removed).
pub fn raw_from_smbios(ids: HardwareIds, os: Option<String>) -> RawIds {
    let ids = ids.sanitized();
    RawIds {
        uuid: ids.system_uuid.map(|u| u.to_vec()),
        serial: ids.system_serial,
        board: ids.board_serial,
        disks: Vec::new(),
        os,
    }
}

// ---- macOS ----

/// Reads `IOPlatformUUID` and `IOPlatformSerialNumber` from `ioreg -rd1 -c
/// IOPlatformExpertDevice` output.
pub fn parse_ioreg(text: &str) -> (Option<String>, Option<String>) {
    fn value(text: &str, key: &str) -> Option<String> {
        let line = text.lines().find(|l| l.contains(key))?;
        let v = line.split('"').nth(3)?.trim();
        (!v.is_empty()).then(|| v.to_string())
    }
    (
        value(text, "\"IOPlatformUUID\"").filter(|v| usable_text(v)),
        value(text, "\"IOPlatformSerialNumber\"").filter(|v| usable_text(v)),
    )
}

/// Raw ids from `ioreg` output.
pub fn raw_from_ioreg(text: &str) -> RawIds {
    let (uuid, serial) = parse_ioreg(text);
    RawIds {
        uuid: uuid.map(|u| u.to_ascii_uppercase().into_bytes()),
        serial,
        ..RawIds::default()
    }
}

// ---- Linux ----

/// Internal-disk identifiers from the names in `/dev/disk/by-id`: ATA, NVMe
/// and virtio disks with a serial in the name; partitions, USB and removable
/// devices, WWN/EUI aliases, device-mapper and RAID names are skipped. Sorted,
/// so the order never changes.
pub fn disk_ids(names: &[String]) -> Vec<String> {
    let mut disks: Vec<String> = names
        .iter()
        .filter(|n| !n.contains("-part"))
        .filter(|n| n.starts_with("ata-") || n.starts_with("virtio-") || is_nvme_with_serial(n))
        .filter(|n| n.chars().count() >= 12 && usable_text(n))
        .cloned()
        .collect();
    disks.sort();
    disks.dedup();
    disks
}

fn is_nvme_with_serial(name: &str) -> bool {
    name.starts_with("nvme-") && !name.starts_with("nvme-eui.") && !name.starts_with("nvme-nvme.")
}

/// A DMI UUID as text (`product_uuid`), unless it is empty or a placeholder.
pub fn parse_dmi_uuid(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let digits: String = t.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if digits.len() != 32 {
        return None;
    }
    let bytes: Vec<u8> = (0..16)
        .filter_map(|i| u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).ok())
        .collect();
    if bytes.len() != 16 || bytes.iter().all(|&b| b == 0) || bytes.iter().all(|&b| b == 0xFF) {
        return None;
    }
    Some(bytes)
}

/// False for empty text and common placeholders.
fn usable_text(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    !matches!(
        lower.as_str(),
        "none" | "unknown" | "default string" | "to be filled by o.e.m." | "n/a" | "not specified"
    )
}

// ---- platform readers ----

#[cfg(target_os = "windows")]
fn read_raw() -> RawIds {
    let ids = windows::smbios_table()
        .map(|table| crate::smbios::parse_rsmb(&table))
        .unwrap_or_default();
    raw_from_smbios(ids, crate::fingerprint::machine_id())
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod windows {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemFirmwareTable(signature: u32, table_id: u32, buffer: *mut u8, size: u32)
            -> u32;
    }

    /// 'RSMB': the raw SMBIOS firmware table provider.
    const RSMB: u32 = 0x5253_4D42;
    /// A real table is a few tens of kilobytes; refuse anything absurd.
    const MAX_TABLE: u32 = 4 * 1024 * 1024;

    /// The raw SMBIOS table with its 8-byte header, if the system provides one.
    pub fn smbios_table() -> Option<Vec<u8>> {
        // SAFETY: GetSystemFirmwareTable with a null buffer and size 0 only
        // returns the size needed; the second call writes at most `size` bytes
        // into a buffer of exactly that length, and returns how many it wrote.
        unsafe {
            let need = GetSystemFirmwareTable(RSMB, 0, std::ptr::null_mut(), 0);
            if need == 0 || need > MAX_TABLE {
                return None;
            }
            let mut buf = vec![0u8; need as usize];
            let got = GetSystemFirmwareTable(RSMB, 0, buf.as_mut_ptr(), need);
            if got == 0 || got > need {
                return None;
            }
            buf.truncate(got as usize);
            Some(buf)
        }
    }
}

#[cfg(target_os = "macos")]
fn read_raw() -> RawIds {
    let text = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let mut raw = raw_from_ioreg(&text);
    raw.os = crate::fingerprint::machine_id();
    raw
}

#[cfg(target_os = "linux")]
fn read_raw() -> RawIds {
    let names: Vec<String> = std::fs::read_dir("/dev/disk/by-id")
        .map(|dir| {
            dir.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    RawIds {
        uuid: std::fs::read_to_string("/sys/class/dmi/id/product_uuid")
            .ok()
            .and_then(|t| parse_dmi_uuid(&t)),
        disks: disk_ids(&names),
        os: crate::fingerprint::machine_id(),
        ..RawIds::default()
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn read_raw() -> RawIds {
    RawIds {
        os: crate::fingerprint::machine_id(),
        ..RawIds::default()
    }
}

/// The signals for this computer. On macOS this runs `ioreg`, so callers should
/// keep the result for the life of the process.
pub fn collect(product: &str) -> Vec<Signal> {
    signals_from(product, &read_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> RawIds {
        RawIds {
            uuid: Some(vec![1; 16]),
            serial: Some("SN-TEST-0001".into()),
            board: Some("BOARD-0002".into()),
            disks: vec!["ata-TEST_DISK_ONE_SERIAL1".into()],
            os: Some("os-machine-id".into()),
        }
    }

    fn kinds(s: &[Signal]) -> Vec<&'static str> {
        s.iter().map(|x| x.kind).collect()
    }

    #[test]
    fn hash_is_sha256_of_product_kind_value() {
        // sha256("POPF|uuid|abc") computed independently (printf | sha256sum).
        assert_eq!(
            hex::encode(signal_hash("POPF", "uuid", b"abc")),
            "a918074140dc84f213373e470a37f0bd386ad6e66c87f73a17473f312cc22859"
        );
    }

    #[test]
    fn hardware_signals_win_and_os_is_left_out() {
        let s = signals_from("POPF", &raw());
        assert_eq!(kinds(&s), ["uuid", "serial", "board", "disk"]);
    }

    #[test]
    fn os_is_the_fallback_only() {
        let only_os = RawIds {
            os: Some("os-machine-id".into()),
            ..RawIds::default()
        };
        assert_eq!(kinds(&signals_from("POPF", &only_os)), ["os"]);
        assert!(signals_from("POPF", &RawIds::default()).is_empty());
    }

    #[test]
    fn same_value_in_two_kinds_gives_different_hashes_and_repeats_collapse() {
        let r = RawIds {
            serial: Some("X1".into()),
            board: Some("X1".into()),
            disks: vec!["ata-SAME_SAME_SAME_1".into(), "ata-SAME_SAME_SAME_1".into()],
            ..RawIds::default()
        };
        let s = signals_from("POPF", &r);
        assert_eq!(kinds(&s), ["serial", "board", "disk"]);
        assert_ne!(s[0].hash, s[1].hash);
    }

    #[test]
    fn different_products_and_values_give_different_hashes() {
        let a = signals_from("POPF", &raw());
        let b = signals_from("LAMP", &raw());
        assert!(a.iter().zip(&b).all(|(x, y)| x.hash != y.hash));
        let mut other = raw();
        other.serial = Some("SN-TEST-0002".into());
        let c = signals_from("POPF", &other);
        assert_ne!(a[1].hash, c[1].hash);
        assert_eq!(a[0].hash, c[0].hash);
    }

    #[test]
    fn at_most_three_disks() {
        let r = RawIds {
            disks: (0..6)
                .map(|i| format!("ata-DISK_NUMBER_{i}_SERIAL"))
                .collect(),
            ..RawIds::default()
        };
        assert_eq!(signals_from("POPF", &r).len(), MAX_DISKS);
    }

    #[test]
    fn hashes_lists_the_raw_bytes() {
        let s = signals_from("POPF", &raw());
        let h = hashes(&s);
        assert_eq!(h.len(), s.len());
        assert_eq!(h[0], s[0].hash);
        assert_eq!(s[0].hash_hex().len(), 64);
    }

    #[test]
    fn smbios_values_become_signals_and_placeholders_do_not() {
        let ids = HardwareIds {
            system_uuid: Some([7; 16]),
            system_serial: Some("To be filled by O.E.M.".into()),
            board_serial: Some("BOARD-7".into()),
        };
        let r = raw_from_smbios(ids, Some("guid".into()));
        assert_eq!(kinds(&signals_from("POPF", &r)), ["uuid", "board"]);
        let nothing = raw_from_smbios(HardwareIds::default(), Some("guid".into()));
        assert_eq!(kinds(&signals_from("POPF", &nothing)), ["os"]);
    }

    #[test]
    fn ioreg_lines_parse() {
        let text = "+-o Root  <class IORegistryEntry>\n    {\n      \"IOPlatformSerialNumber\" = \"C02TESTSERIAL\"\n      \"IOPlatformUUID\" = \"11111111-2222-3333-4444-555555555555\"\n      \"model\" = <\"Mac\">\n    }\n";
        assert_eq!(
            parse_ioreg(text),
            (
                Some("11111111-2222-3333-4444-555555555555".to_string()),
                Some("C02TESTSERIAL".to_string())
            )
        );
        assert_eq!(parse_ioreg(""), (None, None));
        assert_eq!(parse_ioreg("\"IOPlatformUUID\" = \"\""), (None, None));
        let r = raw_from_ioreg(text);
        assert_eq!(kinds(&signals_from("POPF", &r)), ["uuid", "serial"]);
        // Letter case in the UUID does not change the signal.
        let lower = text.replace(
            "11111111-2222-3333-4444-555555555555",
            "abcdefab-2222-3333-4444-555555555555",
        );
        let upper = text.replace(
            "11111111-2222-3333-4444-555555555555",
            "ABCDEFAB-2222-3333-4444-555555555555",
        );
        assert_eq!(
            signals_from("POPF", &raw_from_ioreg(&lower)),
            signals_from("POPF", &raw_from_ioreg(&upper))
        );
    }

    #[test]
    fn disk_ids_keep_internal_disks_only() {
        let names: Vec<String> = [
            "ata-Samsung_SSD_860_EVO_500GB_S3Z2NB0K123456A",
            "ata-Samsung_SSD_860_EVO_500GB_S3Z2NB0K123456A-part1",
            "nvme-Samsung_SSD_970_EVO_Plus_1TB_S4EWNX0M123456A",
            "nvme-Samsung_SSD_970_EVO_Plus_1TB_S4EWNX0M123456A_1",
            "nvme-Samsung_SSD_970_EVO_Plus_1TB_S4EWNX0M123456A-part2",
            "nvme-eui.0025385b21412345",
            "wwn-0x5002538e40123456",
            "usb-SanDisk_Cruzer_4C530001230000000000-0:0",
            "dm-name-vg0-root",
            "lvm-pv-uuid-abcdef",
            "md-uuid-1234",
            "virtio-disk0serial",
            "ata-",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let got = disk_ids(&names);
        assert_eq!(
            got,
            [
                "ata-Samsung_SSD_860_EVO_500GB_S3Z2NB0K123456A",
                "nvme-Samsung_SSD_970_EVO_Plus_1TB_S4EWNX0M123456A",
                "nvme-Samsung_SSD_970_EVO_Plus_1TB_S4EWNX0M123456A_1",
                "virtio-disk0serial",
            ]
        );
        assert!(disk_ids(&[]).is_empty());
    }

    #[test]
    fn dmi_uuid_text_parses_and_placeholders_do_not() {
        let got = parse_dmi_uuid("0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9\n").unwrap();
        assert_eq!(got.len(), 16);
        assert_eq!(got[0], 0x0a);
        assert_eq!(got[15], 0xf9);
        assert_eq!(parse_dmi_uuid("00000000-0000-0000-0000-000000000000"), None);
        assert_eq!(parse_dmi_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff"), None);
        assert_eq!(parse_dmi_uuid(""), None);
        assert_eq!(parse_dmi_uuid("not a uuid"), None);
        assert_eq!(parse_dmi_uuid("1234"), None);
    }

    #[test]
    fn collecting_on_this_computer_does_not_panic() {
        let a = collect("POPF");
        let b = collect("POPF");
        assert_eq!(a, b, "two reads must agree");
        let h = hashes(&a);
        for (i, x) in h.iter().enumerate() {
            assert!(!h[i + 1..].contains(x), "repeated signal");
        }
    }
}
