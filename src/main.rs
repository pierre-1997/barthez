mod globals;
mod header;
mod packet;
mod question;
mod record;
mod result;

use crate::header::Header;
use crate::packet::{DnsPacket, PacketBuffer};
use crate::question::Question;
use crate::record::Record;
use crate::result::{Error, Result};

use std::fs::File;
use std::io::Read;

fn main() -> Result<()> {
    let mut fd = File::open("data/dns_question.bin").map_err(|_| Error::InvalidInputPath)?;
    let mut buffer = PacketBuffer::new();
    fd.read(&mut buffer.bytes)
        .map_err(|_| Error::FailedReadingFile)?;

    let packet = DnsPacket::try_from(buffer)?;
    println!("{}", packet);

    println!("------------------------------------");

    let mut fd = File::open("data/dns_answer.bin").map_err(|_| Error::InvalidInputPath)?;
    let mut buffer = PacketBuffer::new();
    fd.read(&mut buffer.bytes)
        .map_err(|_| Error::FailedReadingFile)?;

    // println!("RAW: {:#?}", &buffer.bytes[0..50]);
    let packet = DnsPacket::try_from(buffer)?;
    println!("{}", packet);

    Ok(())
}
