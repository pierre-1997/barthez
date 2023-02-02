mod globals;
mod header;
mod packet;
mod question;
mod record;
mod result;
mod server;

use crate::header::Header;
use crate::packet::{Packet, PacketBuffer};
use crate::question::Question;
use crate::record::Record;
use crate::record::RecordType;
use crate::result::{Error, Result};
use crate::server::Server;

use std::fs::File;
use std::io::Read;
use std::net::UdpSocket;

fn main() -> Result<()> {
    let mut fd = File::open("data/dns_question.bin").map_err(|_| Error::InvalidInputPath)?;
    let mut buffer = PacketBuffer::new();
    fd.read(&mut buffer.bytes)
        .map_err(|_| Error::FailedReadingFile)?;

    let packet = Packet::try_from(buffer)?;
    println!("{}", packet);

    println!("------------------------------------");

    let mut fd = File::open("data/dns_answer.bin").map_err(|_| Error::InvalidInputPath)?;
    let mut buffer = PacketBuffer::new();
    fd.read(&mut buffer.bytes)
        .map_err(|_| Error::FailedReadingFile)?;

    // println!("RAW: {:#?}", &buffer.bytes[0..50]);
    let packet = Packet::try_from(buffer)?;
    println!("{}", packet);

    println!("------------------------------------");

    let server = Server::new("0.0.0.0".to_string(), 43210);
    let p = server.lookup("yahoo.com", RecordType::MX)?;
    println!("{}", p);

    println!("------------------------------------");

    // Bind an UDP socket on port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053)).map_err(|_| Error::UDPBindFailed)?;

    println!("Running server [{:?}]", socket);

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match server.handle_query(&socket) {
            Ok(_) => {}
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
