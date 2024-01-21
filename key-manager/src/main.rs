use pqcrypto::prelude::*;
use pqcrypto::sign::sphincsshake128ssimple::*;

fn main() {
    let (pk, sk) = keypair();
    std::fs::write("public-key.bin", pk.as_bytes()).unwrap();
    std::fs::write("secret-key.bin", sk.as_bytes()).unwrap();
}
