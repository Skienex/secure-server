use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use secure_common::encryption::Encrypted;
use secure_common::sign;

pub struct Connection<'a> {
    stream: Encrypted<&'a mut TcpStream>,
}

impl<'a> Connection<'a> {
    pub fn establish(
        stream: &'a mut TcpStream,
        client_sk: &sign::SecretKey,
        server_pk: &sign::PublicKey,
    ) -> Result<Self> {
        let mut stream = Encrypted::request(stream)?;
        stream.verify(server_pk)?;
        stream.authorize(client_sk)?;
        Ok(Self { stream })
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        self.stream.send(data)
    }

    pub fn receive(&mut self, len: usize) -> Result<Vec<u8>> {
        self.stream.receive(len)
    }
}

fn main() -> Result<()> {
    let client_sk = sign::read_sk("client.sk")?;
    let server_pk = sign::read_pk("server.pk")?;
    let mut stream = TcpStream::connect("localhost:12345")?;
    let mut conn = Connection::establish(&mut stream, &client_sk, &server_pk)?;
    loop {
        let bytes = conn.receive(16)?;
        if !bytes.is_empty() {
            println!("Message from server: {:?}", String::from_utf8_lossy(&bytes));
            thread::sleep(Duration::from_millis(300));
            conn.send(b"01234567890abcdef")?;
        }
    }
}
