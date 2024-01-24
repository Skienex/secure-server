pub use pqcrypto::sign::sphincsshake128ssimple::{
    detached_sign, signature_bytes, verify_detached_signature, DetachedSignature, PublicKey,
    SecretKey,
};

use std::{fs, path::Path};

use anyhow::Result;
use pqcrypto::prelude::*;

pub fn read_pk<P: AsRef<Path>>(path: P) -> Result<PublicKey> {
    let bytes = fs::read(path)?;
    let key = PublicKey::from_bytes(&bytes)?;
    Ok(key)
}

pub fn read_sk<P: AsRef<Path>>(path: P) -> Result<SecretKey> {
    let bytes = fs::read(path)?;
    let key = SecretKey::from_bytes(&bytes)?;
    Ok(key)
}
