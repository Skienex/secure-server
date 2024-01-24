use std::fs;

use pqcrypto::prelude::*;
use pqcrypto::sign::sphincsshake128ssimple::*;

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| "key".into());
    let (pk, sk) = keypair();
    fs::write(format!("{name}.pk"), pk.as_bytes()).unwrap();
    fs::write(format!("{name}.sk"), sk.as_bytes()).unwrap();
}
