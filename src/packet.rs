use std::fmt::{self, Formatter};
use std::io::Write;
use std::net::Ipv4Addr;

use crate::globals::MAX_JUMPS;
use crate::record::RecordType;
use crate::Header;
use crate::Question;
use crate::Record;
use crate::{Error, Result};

// TODO: might be able to completely delete `PacketBuffer` by implementing `std::io::Read` trait
// for `Question`, `Record` and `Header`.
#[derive(Debug)]
pub struct PacketBuffer {
    /// Bytes array containing a RAW DNS packet
    pub bytes: [u8; 512],
    /// Current position in the bytes array
    pos: usize,
    /// Shadowed actual bit position
    _bit_pos: usize,
}

impl PacketBuffer {
    pub fn new() -> Self {
        Self {
            bytes: [0; 512],
            pos: 0,
            _bit_pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Instead of writting this code everywhere...
    fn check_pos(&self) -> Result<()> {
        if self.pos >= 512 {
            return Err(Error::PacketBufferOver512(format!(
                "check_pos(): self.pos = {}",
                self.pos
            )));
        }

        Ok(())
    }

    /// Gets byte `n` without consuming it
    fn get(&self, n: usize) -> Result<u8> {
        if n >= 512 {
            return Err(Error::PacketBufferOver512(format!("get(): n = {}", n)));
        }

        Ok(self.bytes[n])
    }

    /// Steps over `n` bytes
    pub fn step(&mut self, n: usize) {
        self.pos += n;
    }

    /// Changes the buffer position
    fn seek(&mut self, n: usize) -> Result<()> {
        if n >= 512 {
            return Err(Error::PacketBufferOver512(format!("seek(): n = {}", n)));
        }

        self.pos = n;
        Ok(())
    }

    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err(Error::PacketBufferOver512(format!(
                "get_range(): start = {}, len = {}",
                start, len
            )));
        }

        Ok(&self.bytes[start..start + len])
    }

    /*
    /// Steps over `n` bits
    fn step_bits(&mut self, n: usize) {}

    fn read_bit(&mut self) -> Result<bool> {
        self.check_pos()?;
        todo!()
    }
    */

    pub fn read_u8(&mut self) -> Result<u8> {
        self.check_pos()?;

        let byte = self.bytes[self.pos];

        // Step over the byte we just read
        self.step(1);

        Ok(byte)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        self.check_pos()?;

        let first = self.read_u8()?;
        let second = self.read_u8()?;

        Ok(((first as u16) << 8) | second as u16)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        self.check_pos()?;

        let one = self.read_u8()?;
        let two = self.read_u8()?;
        let three = self.read_u8()?;
        let four = self.read_u8()?;

        Ok(((one as u32) << 24) | ((two as u32) << 16) | ((three as u32) << 8) | (four as u32))
    }

    pub fn read_qname(&mut self) -> Result<String> {
        // Keep track of the number of jumps in order to cap it to `MAX_JUMPS`
        let mut jumps = 0;
        // Tells wether or not we jumped at least once
        let mut jumped = false;
        // Keep track of the current position in the buffer locally (in case of jumps)
        let mut local_pos = self.pos();
        // Initialize the delimiter to empty to push it even at the begining of the output
        let mut delim = "";

        // The output parsed domain
        let mut output = String::new();

        // Loop until reaching the empty byte end of NAME (or if too many jumps)
        loop {
            // Prevent malicious infinite jumps
            if jumps >= MAX_JUMPS {
                return Err(Error::MaxJumpsAttained);
            }

            // We are at the begining of a label, get the length byte (not consuming !!)
            let label_len = self.get(local_pos)?;

            /*
             * NOTE: From https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
             *
             *    1  2  3  4  5  6  7  8  9   .... .. .       16
             *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
             *  | 1  1|                OFFSET                   |
             *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
             *
             *  If the first 2 bits of the length byte are `11`, it means the rest of the 2 byte
             *  word is a pointer to the actual NAME. If so, extract that pointer and set the
             *  `local_pos` variable to that value.
             */
            if (label_len & 0xC0) == 0xC0 {
                // If we didn't jump yet, seek after the two-bytes pointer.
                if !jumped {
                    self.seek(local_pos + 2)?;
                }

                // Build the offset value (6 last bits of length + 8 bits of next byte)
                let offset = (((label_len ^ 0xC0) as u16) << 8) | (self.get(local_pos + 1)? as u16);
                local_pos = offset as usize;
                // Store that we jumped once more
                jumped = true;
                jumps += 1;

                continue;
            } else {
                // Update the local pos to after length-byte we just read
                local_pos += 1;
                // If the length byte is 0 we finished reading the current label
                if label_len == 0 {
                    break;
                }

                // Push the delim in any case (will be empty the first time)
                output.push_str(delim);

                // Get the label's bytes, converts them to a string, append to the output
                let label_bytes = self.get_range(local_pos, label_len as usize)?;
                // NOTE: Are domain names really case insensitive ?
                output.push_str(&String::from_utf8_lossy(label_bytes).to_lowercase());

                // Make sure to push dots as the delimiter from now on
                delim = ".";
                // Move after the label we just read
                local_pos += label_len as usize;
            }
        }

        // If we never jumped, update the buffer's position using the up-to-date `local_pos` var
        if !jumped {
            self.seek(local_pos)?;
        }

        Ok(output)
    }

    /*     WRITE    */
    pub fn write_u8(&mut self, value: u8) -> Result<()> {
        self.check_pos()?;

        self.bytes[self.pos] = value;
        self.pos += 1;

        Ok(())
    }

    pub fn write_u16(&mut self, value: u16) -> Result<()> {
        self.write_u8((value >> 8) as u8)?;
        self.write_u8((value & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, value: u32) -> Result<()> {
        self.write_u8((value >> 24) as u8)?;
        self.write_u8(((value >> 16) & 0xFF) as u8)?;
        self.write_u8(((value >> 8) & 0xFF) as u8)?;
        self.write_u8((value & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
        // Write each part of the domain
        for label in qname.split('.') {
            // Double check the label length isn't over 63
            let len = label.len();
            if len >= 63 {
                return Err(Error::LabelLengthOver63);
            }

            // Write label's length on 1 byte, followed by the label itself
            self.write_u8(len as u8)?;
            for b in label.bytes() {
                self.write_u8(b)?;
            }
        }

        // Write empty byte at end of qname
        self.write_u8(0)?;

        Ok(())
    }

    /* SET */
    fn set_u8(&mut self, pos: usize, value: u8) -> Result<()> {
        if pos >= 512 {
            return Err(Error::PacketBufferOver512(format!(
                "Cannot set value at {}",
                pos
            )));
        }

        self.bytes[pos] = value;
        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, value: u16) -> Result<()> {
        self.set_u8(pos, ((value >> 8) & 0x00FF) as u8)?;
        self.set_u8(pos, (value & 0x00FF) as u8)?;
        Ok(())
    }

    /*
    pub fn _write_range(&mut self, values: &[u8]) -> Result<()> {
        if self.pos + values.len() >= 512 {
            return Err(Error::FailedWritingBuffer(format!(
                "Cannot write data of len {} at {}",
                values.len(),
                self.pos()
            )));
        }

        // self.bytes[self.pos..self.pos + values.len()] = values;

        Ok(())
    }
    */
}

impl Write for PacketBuffer {
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        for b in buf {
            self.write_u8(*b)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        unreachable!();
    }
}

impl From<[u8; 512]> for PacketBuffer {
    fn from(bytes: [u8; 512]) -> Self {
        Self {
            bytes,
            pos: 0,
            _bit_pos: 0,
        }
    }
}

/*
impl TryFrom<Packet> for PacketBuffer {
    type Error = Error;

    fn try_from(mut packet: Packet) -> Result<Self> {
        let buffer = PacketBuffer::new();

        // TODO: Here, define a strategy to build/convert a packet into a PacketBuffer
        /*
        buffer
            .write(packet.as_bytes())
            .map_err(|e| Error::FailedWritingBuffer(e.to_string()))?;
        */

        Ok(buffer)
    }
}
*/

/// From [RFCxxx]():
/// ```
/// +---------------------+
/// |        Header       |
/// +---------------------+
/// |       Question      | the question for the name server
/// +---------------------+
/// |        Answer       | RRs answering the question
/// +---------------------+
/// |      Authority      | RRs pointing toward an authority
/// +---------------------+
/// |      Additional     | RRs holding additional information
/// +---------------------+
/// ```
///
#[derive(Default)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Packet {
    pub fn add_question(&mut self, qname: &str, qtype: RecordType) -> Result<()> {
        self.questions.push(Question::new(qname, qtype));
        self.header.question_count += 1;

        Ok(())
    }

    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|record| match record {
            Record::A { addr, .. } => Some(*addr),
            _ => None,
        })
    }

    fn match_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities.iter().filter_map(|record| match record {
            Record::NS { preamble, host } => {
                if qname.ends_with(&preamble.name) {
                    Some((preamble.name.as_str(), host.as_str()))
                } else {
                    None
                }
            }
            _ => None,
        })
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.match_ns(qname)
            .flat_map(|(_, host)| {
                self.additionals
                    .iter()
                    .filter_map(move |record| match record {
                        Record::A { preamble, addr, .. } if preamble.name == host => Some(*addr),
                        _ => None,
                    })
            })
            .next()
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&str> {
        self.match_ns(qname).map(|(_, host)| host).next()
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        self.header.write(buffer)?;
        for question in &self.questions {
            question.write(buffer)?;
        }

        for answer in &self.answers {
            answer.write(buffer)?;
        }
        for authority in &self.authorities {
            authority.write(buffer)?;
        }
        for additional in &self.additionals {
            additional.write(buffer)?;
        }

        Ok(())
    }
}

impl TryFrom<PacketBuffer> for Packet {
    type Error = Error;

    fn try_from(mut buffer: PacketBuffer) -> Result<Self> {
        // Parsing header
        let header = Header::try_from(&mut buffer)?;

        // Parsing questions
        let mut questions = Vec::new();
        for _ in 0..header.question_count {
            questions.push(Question::try_from(&mut buffer)?);
        }

        // Parsing answers
        let mut answers = Vec::new();
        for _ in 0..header.answer_count {
            answers.push(Record::try_from(&mut buffer)?);
        }

        // Parsing authorities
        let mut authorities = Vec::new();
        for _ in 0..header.authority_count {
            authorities.push(Record::try_from(&mut buffer)?);
        }

        // Parsing additionals
        let mut additionals = Vec::new();
        for _ in 0..header.additional_count {
            additionals.push(Record::try_from(&mut buffer)?);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.header)?;

        if !self.questions.is_empty() {
            writeln!(f, "Questions [")?;
            for (i, question) in self.questions.iter().enumerate() {
                write!(f, "{}", question)?;
                if i < self.questions.len() - 1 {
                    writeln!(f, ",")?;
                }
            }
            writeln!(f, "]\n")?;
        }

        if !self.answers.is_empty() {
            writeln!(f, "Answers [")?;
            for (i, answer) in self.answers.iter().enumerate() {
                write!(f, "{}", answer)?;
                if i < self.answers.len() - 1 {
                    writeln!(f, ",")?;
                }
            }
            writeln!(f, "]\n")?;
        }

        if !self.authorities.is_empty() {
            for (i, authority) in self.authorities.iter().enumerate() {
                writeln!(f, "{}", authority)?;
                if i < self.answers.len() - 1 {
                    writeln!(f, ",")?;
                }
            }
        }

        if !self.additionals.is_empty() {
            writeln!(f, "Additionals [")?;
            for (i, additional) in self.additionals.iter().enumerate() {
                writeln!(f, "{}", additional)?;
                if i < self.additionals.len() - 1 {
                    writeln!(f, ",")?;
                }
            }
            writeln!(f, "]\n")?;
        }

        Ok(())
    }
}
