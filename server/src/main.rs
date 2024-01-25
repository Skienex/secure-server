use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use anyhow::Result;

use chrono::{Datelike, Local, Timelike};
use secure_common::encryption::Encrypted;
use secure_common::sign;

pub struct Connection<'a> {
    stream: Encrypted<&'a mut TcpStream>,
    logger: Logger,
}

impl<'a> Connection<'a> {
    pub fn establish(
        stream: &'a mut TcpStream,
        address: &SocketAddr,
        server_sk: &sign::SecretKey,
        client_pk: &sign::PublicKey,
    ) -> Result<Self> {
        let mut stream = Encrypted::accept(stream)?;
        let logger = Logger::create(&address)?;
        stream.authorize(server_sk)?;
        stream.verify(client_pk)?;
        Ok(Self { stream, logger })
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        self.stream.send(data)
    }

    pub fn receive(&mut self, len: usize) -> Result<Vec<u8>> {
        self.stream.receive(len)
    }
}

pub struct Logger {
    file: fs::File,
}

impl Logger {
    pub fn create(address: &SocketAddr) -> Result<Self> {
        let now = Local::now();
        let ip = match address {
            SocketAddr::V4(addr) => addr.to_string(),
            SocketAddr::V6(addr) => addr.to_string(),
        };
        let log_name = format!(
            "logs/log-{:04}-{:02}-{:02}-{:02}-{:02}-{:02}.txt",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
        );
        let file = fs::File::create(log_name)?;
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

fn handle_client(
    stream: &mut TcpStream,
    address: &SocketAddr,
    server_sk: &sign::SecretKey,
    client_pk: &sign::PublicKey,
) -> Result<()> {
    println!("Establishing connection to {address}");
    let mut conn = Connection::establish(stream, address, server_sk, client_pk)?;
    println!("Connection to {address} established");
    conn.send(b"....----....----")?;
    loop {
        let bytes = conn.receive(16)?;
        if !bytes.is_empty() {
            println!("Message from client: {:?}", String::from_utf8_lossy(&bytes));
            thread::sleep(Duration::from_secs(2));
            conn.send(b"fedcba9876543210")?;
        }
    }
}

fn main() -> Result<()> {
    let server_sk = sign::read_sk("server.sk")?;
    let client_pk = sign::read_pk("client.pk")?;
    println!("Successfully read keys");
    let listener = TcpListener::bind("localhost:12345")?;
    println!("Listening...");
    thread::scope(move |scope| loop {
        let (mut stream, address) = match listener.accept() {
            Ok(ok) => ok,
            Err(err) => {
                eprintln!("Error: {err}");
                break;
            }
        };
        scope.spawn(move || {
            if let Err(err) = handle_client(&mut stream, &address, &server_sk, &client_pk) {
                eprintln!("Error: {err}");
            }
        });
    });
    Ok(())
}
