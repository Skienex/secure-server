use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use openssl::hash::{hash, MessageDigest};
use openssl::symm::{decrypt, encrypt, Cipher};
use pqcrypto::kem::kyber1024::{self, encapsulate, SharedSecret};
use pqcrypto::prelude::*;
use pqcrypto::sign::sphincsshake128ssimple;

use chrono::{Datelike, Local, Timelike};

pub struct Connection<'a> {
    stream: &'a mut TcpStream,
    shared_secret: SharedSecret,
    cipher: Cipher,
    iv: Vec<u8>,
    logger: Logger,
}

impl<'a> Connection<'a> {
    pub fn establish(
        stream: &'a mut TcpStream,
        address: &SocketAddr,
        server_sk: Rc<sphincsshake128ssimple::SecretKey>,
        client_pk: Rc<sphincsshake128ssimple::PublicKey>,
    ) -> Result<Self> {
        let mut pk_bytes = [0; 1568];
        stream.read_exact(&mut pk_bytes)?;
        let pk = kyber1024::PublicKey::from_bytes(&pk_bytes)?;
        let (ss, ct) = encapsulate(&pk);
        stream.write_all(ct.as_bytes())?;
        ss.as_bytes();
        let cipher = Cipher::aes_256_cbc();
        let digest = MessageDigest::shake_128();
        let iv = hash(digest, ss.as_bytes())?.to_vec();
        let logger = Logger::create(&address)?;
        let sig = sphincsshake128ssimple::detached_sign(ss.as_bytes(), &server_sk);

        let encrypted_sig = encrypt(cipher, ss.as_bytes(), Some(&iv), sig.as_bytes())?;
        stream.write_all(&encrypted_sig)?;

        let mut sig_bytes = [0u8; 7856];

        stream.read_exact(&mut sig_bytes)?;
        let decrypted_sig_bytes = decrypt(cipher, ss.as_bytes(), Some(&iv), &sig_bytes)?;
        let sig = sphincsshake128ssimple::DetachedSignature::from_bytes(&decrypted_sig_bytes)?;
        sphincsshake128ssimple::verify_detached_signature(&sig, ss.as_bytes(), &client_pk)?;

        Ok(Self {
            cipher,
            stream,
            shared_secret: ss,
            iv,
            logger,
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
        self.logger.info(&format!(
            "Sent '{:?}' to server.",
            String::from_utf8_lossy(data)
        ))?;
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
        self.logger.info(&format!(
            "Received: '{:?}'",
            String::from_utf8_lossy(&bytes)
        ))?;
        Ok(bytes)
    }
}

pub struct Logger {
    file: File,
}

impl Logger {
    pub fn create(address: &SocketAddr) -> Result<Self> {
        let now = Local::now();
        let ip = match address {
            SocketAddr::V4(addr) => addr.to_string(),
            SocketAddr::V6(addr) => addr.to_string(),
        };
        let log_name = format!(
            "logs\\log-{:04}-{:02}-{:02}-{:02}-{:02}-{:02}.txt",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
        );
        let file = File::create(log_name)?;
        let mut logger = Self { file };
        logger.info(&format!("Client connected with ip: {}", ip))?;
        Ok(logger)
    }

    pub fn info(&mut self, message: &str) -> Result<()> {
        let now = Local::now();
        writeln!(
            self.file,
            "[{:04}-{:02}-{:02}-{:02}-{:02}-{:02}] INFO > {:?}",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            message
        )?;
        Ok(())
    }

    pub fn error(&mut self, message: &str) -> Result<()> {
        let now = Local::now();
        writeln!(
            self.file,
            "[{:04}-{:02}-{:02}-{:02}-{:02}-{:02}] ERROR > {:?}",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            message
        )?;
        Ok(())
    }
}

fn main() -> Result<()> {
    let listener = TcpListener::bind("localhost:12345")?;
    thread::scope(move |scope| loop {
        let (mut stream, address) = match listener.accept() {
            Ok(ok) => ok,
            Err(err) => {
                eprintln!("Error: {err}");
                break;
            }
        };
        scope.spawn(move || {
            if let Err(err) = handle_client(&mut stream, &address) {
                eprintln!("Error: {err}");
            }
        });
    });
    Ok(())
}

fn handle_client(stream: &mut TcpStream, address: &SocketAddr) -> Result<()> {
    let mut conn = Connection::establish(stream, address)?;
    conn.send_raw(b"Server Nachricht")?;
    loop {
        let bytes = conn.receive_raw(1024)?;
        if !bytes.is_empty() {
            thread::sleep(Duration::from_secs(2));
            let _ = conn.send_raw(b"From Server");
        }
    }
}
