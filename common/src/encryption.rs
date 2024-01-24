use std::io::{Read, Write};

use anyhow::Result;
use openssl::{
    hash::{hash, MessageDigest},
    symm::{decrypt, encrypt, Cipher},
};
use pqcrypto::traits::{
    kem::{Ciphertext, PublicKey, SharedSecret},
    sign::DetachedSignature,
};

/// Get the cipher to use
fn cipher() -> Cipher {
    Cipher::aes_256_cbc()
}

pub struct Encrypted<T> {
    stream: T,
    shared_secret: crate::key_exchange::SharedSecret,
    cipher: Cipher,
    iv: Vec<u8>,
}

impl<T> Encrypted<T>
where
    T: Read + Write,
{
    pub fn request(mut stream: T) -> Result<Self> {
        let (pk, sk) = crate::key_exchange::keypair();
        stream.write_all(pk.as_bytes())?;
        let mut ct_bytes = [0; crate::key_exchange::ciphertext_bytes()];
        stream.read_exact(&mut ct_bytes)?;
        let ct = crate::key_exchange::Ciphertext::from_bytes(&ct_bytes)?;
        let ss = crate::key_exchange::decapsulate(&ct, &sk);
        let cipher = cipher();
        let digest = MessageDigest::shake_128();
        let iv = hash(digest, ss.as_bytes())?.to_vec(); // Create iv from shared secret
        Ok(Self {
            stream,
            shared_secret: ss,
            cipher,
            iv,
        })
    }

    pub fn accept(mut stream: T) -> Result<Self> {
        let mut pk_bytes = [0; crate::key_exchange::public_key_bytes()];
        stream.read_exact(&mut pk_bytes)?;
        let pk = crate::key_exchange::PublicKey::from_bytes(&pk_bytes)?;
        let (ss, ct) = crate::key_exchange::encapsulate(&pk);
        stream.write_all(ct.as_bytes())?;
        let cipher = cipher();
        let digest = MessageDigest::shake_128();
        let iv = hash(digest, ss.as_bytes())?.to_vec(); // Create iv from shared secret
        Ok(Self {
            stream,
            shared_secret: ss,
            cipher,
            iv,
        })
    }

    /// Receive and verify signature
    pub fn verify(&mut self, pk: &crate::sign::PublicKey) -> Result<()> {
        let sig_bytes = self.receive(crate::sign::signature_bytes())?;
        let sig = crate::sign::DetachedSignature::from_bytes(&sig_bytes)?;
        crate::sign::verify_detached_signature(&sig, self.shared_secret.as_bytes(), &pk)?;
        Ok(())
    }

    /// Send signature
    pub fn authorize(&mut self, sk: &crate::sign::SecretKey) -> Result<()> {
        let sig = crate::sign::detached_sign(self.shared_secret.as_bytes(), sk);
        self.send(sig.as_bytes())?;
        Ok(())
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        println!("pre-send: {}", data.len());
        let encrypted = encrypt(
            self.cipher,
            self.shared_secret.as_bytes(),
            Some(&self.iv),
            data,
        )?;
        println!("post-send: {}", encrypted.len());
        self.stream.write_all(&encrypted)?;
        Ok(())
    }

    pub fn receive(&mut self, mut size: usize) -> Result<Vec<u8>> {
        size += 16 - size % 16;
        println!("pre-receive: {size}");
        let mut buf = vec![0; size];
        self.stream.read_exact(&mut buf)?;
        let decrypted = decrypt(
            self.cipher,
            self.shared_secret.as_bytes(),
            Some(&self.iv),
            &buf,
        )?;
        println!("post-receive: {}", decrypted.len());
        Ok(decrypted)
    }
}
