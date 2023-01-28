use std::fmt::{self, Formatter};

use crate::packet::PacketBuffer;
use crate::record::RecordType;
use crate::result::{Error, Result};

pub struct Question {
    name: String,
    /// 2 bytes. The record type.
    question_type: RecordType,
    _class: u16,
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
        let name = buffer.read_next_name()?;
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
