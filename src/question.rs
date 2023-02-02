use std::fmt::{self, Formatter};

use crate::packet::PacketBuffer;
use crate::record::RecordType;
use crate::result::{Error, Result};

pub struct Question {
    pub name: String,
    /// 2 bytes. The record type.
    pub question_type: RecordType,
    _class: u16,
}

impl Question {
    pub fn new(qname: &str, qtype: RecordType) -> Self {
        Self {
            name: qname.to_owned(),
            question_type: qtype,
            _class: 1,
        }
    }

    /// From [RFC1035#4.1.2](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.2)
    /// ```
    ///                                 1  1  1  1  1  1
    ///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                                               |
    /// /                     QNAME                     /
    /// /                                               /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                     QTYPE                     |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                     QCLASS                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;
        buffer.write_u16(self.question_type.into())?;
        buffer.write_u16(self._class)?;

        Ok(())
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "{{")?;
        writeln!(f, "\tName: {}", self.name)?;
        writeln!(f, "\tType: {}", self.question_type)?;
        writeln!(f, "}}")?;

        Ok(())
    }
}

impl TryFrom<&mut PacketBuffer> for Question {
    type Error = Error;
    fn try_from(buffer: &mut PacketBuffer) -> Result<Self> {
        let name = buffer.read_qname()?;
        let question_type = RecordType::from(buffer.read_u16()?);
        let _class = buffer.read_u16()?;

        if _class != 1 {
            eprintln!("Strange, class of question {} != 1.", name);
        }

        Ok(Self {
            name,
            question_type,
            _class,
        })
    }
}
