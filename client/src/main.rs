use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::Result;
use openssl::hash::{hash, MessageDigest};
use openssl::symm::{decrypt, encrypt, Cipher};
use pqcrypto::kem::kyber1024::{decapsulate, Ciphertext, SharedSecret};
use pqcrypto::prelude::*;
use pqcrypto::sign::sphincsshake128ssimple;
use secure_common::{key_exchange, sign};

pub struct Connection<'a> {
    stream: &'a mut TcpStream,
    shared_secret: SharedSecret,
    cipher: Cipher,
    iv: Vec<u8>,
}

impl<'a> Connection<'a> {
    pub fn establish(
        stream: &'a mut TcpStream,
        client_sk: &sign::SecretKey,
        server_pk: &sign::PublicKey,
    ) -> Result<Self> {
        let (pk, sk) = secure_common::key_exchange::keypair();
        stream.write_all(pk.as_bytes())?;
        let mut ct_bytes = [0; 1568];
        stream.read_exact(&mut ct_bytes)?;
        let ct = Ciphertext::from_bytes(&ct_bytes)?;
        let ss = decapsulate(&ct, &sk);
        let cipher = Cipher::aes_256_cbc();
        let digest = MessageDigest::shake_128();
        let iv = hash(digest, ss.as_bytes())?.to_vec();
        // Verify server signature
        let mut sig_bytes = [0u8; 7856];
        stream.read_exact(&mut sig_bytes)?;
        let decrypted_sig_bytes = decrypt(cipher, ss.as_bytes(), Some(&iv), &sig_bytes)?;
        let sig = sign::DetachedSignature::from_bytes(&decrypted_sig_bytes)?;
        sign::verify_detached_signature(&sig, ss.as_bytes(), &server_pk)?;
        // Send client signature
        let sig = sign::detached_sign(ss.as_bytes(), &client_sk);
        let encrypted_sig = encrypt(cipher, ss.as_bytes(), Some(&iv), sig.as_bytes())?;
        stream.write_all(&encrypted_sig)?;
        Ok(Self {
            stream,
            shared_secret: ss,
            cipher,
            iv,
        })
    }

    pub fn send_raw(&mut self, data: &[u8]) -> Result<()> {
        let output = encrypt(
            self.cipher,
            self.shared_secret.as_bytes(),
            Some(&self.iv),
            data,
        )?;
        self.stream.write_all(&output)?;
        Ok(())
    }

    pub fn receive_raw(&mut self, max_len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0; max_len];
        let len = self.stream.read(&mut buf)?;
        if len == 0 {
            return Ok(Vec::new());
        }
        let bytes = decrypt(
            self.cipher,
            self.shared_secret.as_bytes(),
            Some(&self.iv),
            &buf[0..len],
        )?;
        Ok(bytes)
    }
}

fn main() -> Result<()> {
    let client_sk = secure_common::sign::read_sk("client.sk")?;
    let server_pk = secure_common::sign::read_pk("server.pk")?;
    let mut stream = TcpStream::connect("localhost:12345")?;
    let mut conn = Connection::establish(&mut stream, &client_sk, &server_pk)?;
    loop {
        let bytes = conn.receive_raw(1024)?;
        if !bytes.is_empty() {
            println!("Received: {:?}", String::from_utf8_lossy(&bytes));
            std::thread::sleep(Duration::from_millis(300));
            let _ = conn.send_raw(b"From Client");
        }
    }
}
