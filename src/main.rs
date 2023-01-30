mod globals;
mod header;
mod packet;
mod question;
mod record;
mod result;

use crate::header::Header;
use crate::packet::{Packet, PacketBuffer};
use crate::question::Question;
use crate::record::Record;
use crate::record::RecordType;
use crate::result::{Error, Result};

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

    // Forge a query packet
    let mut send_packet: Packet = Default::default();
    send_packet.header.recursion_desired = true;
    send_packet.add_question("archlinux.com", RecordType::A)?;

    // Write that packet to a buffer to send
    let mut send_buffer = PacketBuffer::new();
    send_packet.write(&mut send_buffer)?;
    println!("Send packet:\n{}", send_packet);

    let server = ("8.8.8.8", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 43210)).map_err(|_| Error::UDPBindFailed)?;
    socket
        .send_to(&send_buffer.bytes[0..send_buffer.pos()], server)
        .map_err(|e| {
            eprintln!("{e}");
            Error::UDPSendFailed
        })?;

    let mut recv_buffer = PacketBuffer::new();
    socket
        .recv_from(&mut recv_buffer.bytes)
        .map_err(|_| Error::UDPRecvFailed)?;

    let recv_packet = Packet::try_from(recv_buffer)?;
    println!("{}", recv_packet);

    Ok(())
}
