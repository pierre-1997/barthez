use core::fmt::{self, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::result::{Error, Result};
use crate::PacketBuffer;

// #![allow(non_camel_case_types)]

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum RecordType {
    Unknown(u16),
    A,  // 1
    NS, // 2
    //#[allow(non_camel_case_types)]
    #[allow(non_camel_case_types)]
    CNAME, // 5
    //#[allow(non_camel_case_types)]
    MX, // 15
    #[allow(non_camel_case_types)]
    AAAA, // 28
}

impl From<RecordType> for u16 {
    fn from(value: RecordType) -> Self {
        match value {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::MX => 15,
            RecordType::AAAA => 28,
            RecordType::Unknown(x) => x,
        }
    }
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            15 => RecordType::MX,
            28 => RecordType::AAAA,
            _ => RecordType::Unknown(value),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::Unknown(_) => write!(f, "Unknown")?,
            RecordType::A => write!(f, "A")?,
            RecordType::NS => write!(f, "NS")?,
            RecordType::CNAME => write!(f, "CNAME")?,
            RecordType::MX => write!(f, "MX")?,
            RecordType::AAAA => write!(f, "AAAA")?,
        }

        Ok(())
    }
}

pub struct RecordPreamble {
    name: String,
    /// 2 bytes
    record_type: RecordType,
    /// 2 bytes. The class, in practice always set to 1.
    _class: u16,
    ttl: u32,
    len: u16,
}

impl fmt::Display for RecordPreamble {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "\tName: {}", self.name)?;
        writeln!(f, "\tType: {}", self.record_type)?;
        writeln!(f, "\t_class: {}", self._class)?;
        writeln!(f, "\tTTL: {}", self.ttl)?;
        writeln!(f, "\tLength: {}", self.len)?;

        Ok(())
    }
}

pub enum Record {
    Unknown {
        preamble: RecordPreamble,
    },
    A {
        preamble: RecordPreamble,
        addr: Ipv4Addr,
    },
    NS {
        preamble: RecordPreamble,
        host: String,
    },
    #[allow(non_camel_case_types)]
    CNAME {
        preamble: RecordPreamble,
        host: String,
    },
    MX {
        preamble: RecordPreamble,
        preference: u16,
        exchange: String,
    },
    #[allow(non_camel_case_types)]
    AAAA {
        preamble: RecordPreamble,
        addr: Ipv6Addr,
    },
}

impl Record {
    /// From [RFC1035#4.1.3](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.3):
    /// ```
    ///                                     1  1  1  1  1  1
    ///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                                               |
    /// /                                               /
    /// /                      NAME                     /
    /// |                                               |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                      TYPE                     |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                     CLASS                     |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                      TTL                      |
    /// |                                               |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                   RDLENGTH                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /// /                     RDATA                     /
    /// /                                               /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    ///
    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        match self {
            Record::A { preamble, addr } => {
                buffer.write_qname(&preamble.name)?;
                buffer.write_u16(RecordType::A.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(preamble.ttl)?;

                // Length of IP address is 4 bytes
                buffer.write_u16(4)?;
                let ip = addr.octets();
                buffer.write_u8(ip[0])?;
                buffer.write_u8(ip[1])?;
                buffer.write_u8(ip[2])?;
                buffer.write_u8(ip[3])?;
            }
            Record::NS { preamble, host } => {
                buffer.write_qname(&preamble.name)?;
                buffer.write_u16(RecordType::NS.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(preamble.ttl)?;

                // We don't know the size of the qname yet,
                // so we write an empty 2 bytes word for now
                let pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_qname(host)?;
                let size = buffer.pos() - pos + 2;
                buffer.set_u16(pos, size as u16)?;
            }
            Record::CNAME { preamble, host } => {
                buffer.write_qname(&preamble.name)?;
                buffer.write_u16(RecordType::CNAME.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(preamble.ttl)?;

                // We don't know the size of the qname yet,
                // so we write an empty 2 bytes word for now
                let pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_qname(host)?;
                let size = buffer.pos() - pos + 2;
                buffer.set_u16(pos, size as u16)?;
            }
            Record::MX {
                preamble,
                preference,
                exchange,
            } => {
                buffer.write_qname(&preamble.name)?;
                buffer.write_u16(RecordType::MX.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(preamble.ttl)?;

                // We don't know the size of the qname yet,
                // so we write an empty 2 bytes word for now
                let pos = buffer.pos();
                buffer.write_u16(0)?;
                // Write the data
                buffer.write_u16(*preference)?;
                buffer.write_qname(exchange)?;
                // Calculate and set the length of the data we just wrote
                let size = buffer.pos() - pos + 2;
                buffer.set_u16(pos, size as u16)?;
            }
            Record::AAAA { preamble, addr } => {
                buffer.write_qname(&preamble.name)?;
                buffer.write_u16(RecordType::AAAA.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(preamble.ttl)?;

                // The size of an IPv6 address is 16 bytes
                buffer.write_u16(16)?;
                for segment in addr.segments() {
                    buffer.write_u16(segment)?;
                }
            }
            _ => {
                println!("Skipping writing record: {}", self);
            }
        }

        Ok(())
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Record::Unknown { preamble } => {
                writeln!(f, "Record::Unknown {{")?;
                write!(f, "{}", preamble)?;
                writeln!(f, "}}")?;
            }
            Record::NS { preamble, host } => {
                writeln!(f, "Record::NS {{")?;
                write!(f, "{}", preamble)?;
                write!(f, "\t{}", host)?;
                writeln!(f, "}}")?;
            }
            Record::CNAME { preamble, host } => {
                writeln!(f, "Record::CNAME {{")?;
                write!(f, "{}", preamble)?;
                write!(f, "\t{}", host)?;
                writeln!(f, "}}")?;
            }
            Record::MX {
                preamble,
                preference,
                exchange,
            } => {
                writeln!(f, "Record::MX {{")?;
                write!(f, "{}", preamble)?;
                writeln!(f, "\tpreference: {}", preference)?;
                writeln!(f, "\texchange: {}", exchange)?;
                writeln!(f, "}}")?;
            }
            Record::A { preamble, addr } => {
                writeln!(f, "Record::A {{")?;
                write!(f, "{}", preamble)?;
                writeln!(f, "\taddr: {}", addr)?;
                writeln!(f, "}}")?;
            }
            Record::AAAA { preamble, addr } => {
                writeln!(f, "Record::AAAA {{")?;
                write!(f, "{}", preamble)?;
                writeln!(f, "\taddr: {}", addr)?;
                writeln!(f, "}}")?;
            }
        }

        Ok(())
    }
}

impl TryFrom<&mut PacketBuffer> for Record {
    type Error = Error;

    fn try_from(buffer: &mut PacketBuffer) -> Result<Self> {
        let name = buffer.read_qname()?;
        let record_type = RecordType::from(buffer.read_u16()?);
        let _class = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let len = buffer.read_u16()?;
        let preamble = RecordPreamble {
            name,
            record_type,
            _class,
            ttl,
            len,
        };

        match preamble.record_type {
            RecordType::A => {
                let one = buffer.read_u8()?;
                let two = buffer.read_u8()?;
                let three = buffer.read_u8()?;
                let four = buffer.read_u8()?;
                let addr = Ipv4Addr::new(one, two, three, four);

                Ok(Record::A { preamble, addr })
            }
            RecordType::NS => {
                let host = buffer.read_qname()?;
                Ok(Record::NS { preamble, host })
            }
            RecordType::CNAME => {
                let host = buffer.read_qname()?;
                Ok(Record::CNAME { preamble, host })
            }
            RecordType::MX => {
                let preference = buffer.read_u16()?;
                let exchange = buffer.read_qname()?;
                Ok(Record::MX {
                    preamble,
                    preference,
                    exchange,
                })
            }
            RecordType::AAAA => {
                let one = buffer.read_u32()?;
                let two = buffer.read_u32()?;
                let three = buffer.read_u32()?;
                let four = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((one >> 16) & 0xFFFF) as u16,
                    (one & 0xFFFF) as u16,
                    ((two >> 16) & 0xFFFF) as u16,
                    (two & 0xFFFF) as u16,
                    ((three >> 16) & 0xFFFF) as u16,
                    (three & 0xFFFF) as u16,
                    ((four >> 16) & 0xFFFF) as u16,
                    (four & 0xFFFF) as u16,
                );

                Ok(Record::AAAA { preamble, addr })
            }
            _ => {
                // Jumps over the non-parsed records length
                buffer.step(preamble.len.into());
                return Ok(Record::Unknown { preamble });
            }
        }
    }
}
