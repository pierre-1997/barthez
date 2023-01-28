use core::fmt::{self, Formatter};
use std::net::Ipv4Addr;

use crate::result::{Error, Result};
use crate::PacketBuffer;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum RecordType {
    Unknown(u16),
    A,
}

impl From<RecordType> for u16 {
    fn from(value: RecordType) -> Self {
        match value {
            RecordType::A => 1,
            RecordType::Unknown(x) => x,
        }
    }
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            _ => RecordType::Unknown(value),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::Unknown(_) => write!(f, "Unknown")?,
            RecordType::A => write!(f, "A")?,
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
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Record::Unknown { preamble } => {
                writeln!(f, "Record::Unknown {{")?;
                write!(f, "{}", preamble)?;
                writeln!(f, "}}")?;
            }
            Record::A { preamble, addr } => {
                writeln!(f, "Record::A {{")?;
                write!(f, "{}", preamble)?;
                writeln!(f, "\t{}", addr)?;
                writeln!(f, "}}")?;
            }
        }

        Ok(())
    }
}

impl TryFrom<&mut PacketBuffer> for Record {
    type Error = Error;

    fn try_from(buffer: &mut PacketBuffer) -> Result<Self> {
        let name = buffer.read_next_name()?;
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
            _ => {
                // Jumps over the non-parsed records length
                buffer.step(preamble.len.into());
                Ok(Record::Unknown { preamble })
            }
        }
    }
}
