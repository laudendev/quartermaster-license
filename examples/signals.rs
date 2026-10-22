//! Prints the hardware signals this computer would send for a free trial:
//! the kind and the first 16 hex characters of each hash (never the raw
//! identifiers). Run `cargo run --example signals` on each platform to check
//! that the hardware identifiers can be read there.

use quartermaster_license::hardware;

fn main() {
    let signals = hardware::collect("POPF");
    if signals.is_empty() {
        println!("no signals could be read");
        return;
    }
    for signal in signals {
        println!("{:<7} {}", signal.kind, &signal.hash_hex()[..16]);
    }
}
