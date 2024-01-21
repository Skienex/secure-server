use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::{Ok, Result};
use openssl::hash::{hash, MessageDigest};
use openssl::symm::{decrypt, encrypt, Cipher};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

struct Connection<'a> {
    stream: &'a mut TcpStream,
    shared_secret: SharedSecret,
    cipher: Cipher,
    iv: Vec<u8>,
}

impl<'a> Connection<'a> {
    pub fn establish(stream: &'a mut TcpStream) -> Result<Self> {
        let client_private = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_private);
        stream.write_all(client_public.as_bytes())?;
        let mut key_bytes = [0; 32];
        stream.read_exact(&mut key_bytes)?;
        let server_public = key_bytes.into();
        let shared_secret = client_private.diffie_hellman(&server_public);
        let cipher = Cipher::aes_256_cbc();
        let digest = MessageDigest::shake_128();
        let iv = hash(digest, shared_secret.as_bytes())?.to_vec();

        Ok(Self {
            cipher,
            shared_secret,
            stream,
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
    let mut stream = TcpStream::connect("localhost:12345")?;
    let mut conn = Connection::establish(&mut stream)?;
    loop {
        let bytes = conn.receive_raw(1024)?;
        if !bytes.is_empty() {
            println!("Received: {:?}", String::from_utf8_lossy(&bytes));
            std::thread::sleep(Duration::from_millis(300));
            let _ = conn.send_raw(b"From Client");
        }
    }
}
