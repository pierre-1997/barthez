mod errors;
// mod globals;

use crate::errors::{Error, Result};
// use crate::globals::{DELIM, MAX_JUMPS};

use core::fmt;
use core::fmt::Formatter;
use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;

// type Error = Box<dyn std::error::Error>;
// type Result<T> = std::result::Result<T, Error>;

// TODO: might be able to completely delete `PacketBuffer` by implementing `std::io::Read` trait
// for `Question`, `Record` and `Header`.
#[derive(Debug)]
struct PacketBuffer {
    bytes: [u8; 512],
    // Current position in bits?
    pos: usize,
}

impl PacketBuffer {
    fn new() -> Self {
        Self {
            bytes: [0; 512],
            pos: 0,
        }
    }
    fn pos(&self) -> usize {
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
        /*
        if n >= 512 {
            return Err(Error::PacketBufferOver512(format!("get(): n = {}", n)));
        }
        */

        Ok(self.bytes[n])
    }

    /// Steps over `n` bytes
    fn step(&mut self, n: usize) {
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

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
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

    fn read_u8(&mut self) -> Result<u8> {
        self.check_pos()?;

        let byte = self.bytes[self.pos];

        // Step over the byte we just read
        self.step(1);

        Ok(byte)
    }

    fn read_u16(&mut self) -> Result<u16> {
        self.check_pos()?;

        let first = self.read_u8()?;
        let second = self.read_u8()?;

        Ok(((first as u16) << 8) | second as u16)
    }

    fn read_u32(&mut self) -> Result<u32> {
        self.check_pos()?;

        let one = self.read_u8()?;
        let two = self.read_u8()?;
        let three = self.read_u8()?;
        let four = self.read_u8()?;

        Ok(((one as u32) << 24) | ((two as u32) << 16) | ((three as u32) << 8) | (four as u32))
    }

    // TODO: REDO the below function using (https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4)
    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn read_qname(&mut self) -> Result<String> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.pos();

        let mut outstr = String::new();
        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(Error::MaxJumpsAttained);
                // return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(outstr)
    }

    /*
    // TODO: Handle jumps !!!
    fn _read_next_name(&mut self) -> Result<String> {
        let mut _jumps = 0;
        let mut output = String::new();
        let mut first = true;

        loop {
            if _jumps >= MAX_JUMPS {
                return Err(Error::MaxJumpsAttained);
            }

            let label_len = self.read_u8()?;
            dbg!(label_len);
            if label_len == 0 {
                break;
            }

            if first {
                first = false;
            } else {
                output.push(DELIM);
            }

            if (label_len & 0xC0) == 0xC0 {}

            for _ in 0..label_len {
                let c = self.read_u8()?;
                let c = char::from_u32(c as u32).unwrap();
                output.push(c);
            }
            dbg!(&output);
        }

        Ok(output)
    }
    */
}

impl From<[u8; 512]> for PacketBuffer {
    fn from(bytes: [u8; 512]) -> Self {
        Self { bytes, pos: 0 }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum QueryType {
    Unknown(u16),
    A,
}

impl From<QueryType> for u16 {
    fn from(value: QueryType) -> Self {
        match value {
            QueryType::A => 1,
            QueryType::Unknown(x) => x,
        }
    }
}

impl From<u16> for QueryType {
    fn from(value: u16) -> Self {
        match value {
            1 => QueryType::A,
            _ => QueryType::Unknown(value),
        }
    }
}

impl fmt::Display for QueryType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            QueryType::Unknown(_) => write!(f, "Unknown")?,
            QueryType::A => write!(f, "A")?,
        }

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl From<u8> for ResultCode {
    fn from(value: u8) -> Self {
        match value {
            // 0 => ResultCode::NOERROR,
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            _ => ResultCode::NOERROR,
        }
    }
}

impl fmt::Display for ResultCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ResultCode::NOERROR => write!(f, "NOERROR"),
            ResultCode::FORMERR => write!(f, "FORMERR"),
            ResultCode::SERVFAIL => write!(f, "SERVFAIL"),
            ResultCode::NXDOMAIN => write!(f, "NXDOMAIN"),
            ResultCode::NOTIMP => write!(f, "NOTIMP"),
            ResultCode::REFUSED => write!(f, "REFUSED"),
        }
    }
}

#[derive(Debug)]
struct Header {
    /// A random identifier is assigned to query packets. Response packets must reply with the
    /// same id. This is needed to differentiate responses due to the stateless nature of UDP.
    id: u16,

    /// 1 bit. 0 for queries, 1 for responses.
    is_response: bool,
    /// 4 bits. Typically always 0, see RFC1035 for details.
    _op_code: u8,
    /// 1 bit. Set to 1 if the responding server is authoritative - that is, it "owns" - the domain queried.
    is_authoritative: bool,
    /// 1 bit. Set to 1 if the message length exceeds 512 bytes. Traditionally a hint that the
    /// query can be reissued using TCP, for which the length limitation doesn't apply.
    is_truncated: bool,
    /// 1 bit. Set by the sender of the request if the server should attempt to resolve the query recursively if it does not have an answer readily available.
    recursion_desired: bool,
    /// 1 bit. Set by the server to indicate whether or not recursive queries are allowed.
    recursion_available: bool,
    /// 3 bits. Originally reserved for later use, but now used for DNSSEC queries.
    _z: u8,

    /// 4 bits. Set by the server to indicate the status of the response, i.e. whether or not it was successful or failed, and in the latter case providing details about the cause of the failure.
    response_code: ResultCode,

    /// 16 bits. The number of entries in the Question Section.
    question_count: u16,
    /// 16 bits. The number of entries in the Answer Section.
    answer_count: u16,
    /// 16 bits. The number of entries in the Authority Section.
    authority_count: u16,
    /// 16 bits. The number of entries in the Additional Section.
    additional_count: u16,
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Header {{")?;
        writeln!(f, "\tID: {}", self.id)?;
        writeln!(
            f,
            "\tis_response: {}",
            if self.is_response { "1" } else { "0" }
        )?;
        writeln!(
            f,
            "\tis_authoritative: {}",
            if self.is_authoritative { "1" } else { "0" }
        )?;
        writeln!(
            f,
            "\tis_truncated: {}",
            if self.is_truncated { "1" } else { "0" }
        )?;
        writeln!(
            f,
            "\tRec. Desired: {}",
            if self.recursion_desired { "1" } else { "0" }
        )?;
        writeln!(
            f,
            "\tRec. Available: {}",
            if self.recursion_available { "1" } else { "0" }
        )?;
        writeln!(f, "\tRCODE: {}", self.response_code)?;
        writeln!(f, "\tNB Questions: {}", self.question_count)?;
        writeln!(f, "\tNB Answers: {}", self.answer_count)?;
        writeln!(f, "\tNB Authorities: {}", self.authority_count)?;
        writeln!(f, "\tNB Additionals: {}", self.additional_count)?;

        writeln!(f, "}}")?;

        Ok(())
    }
}

impl TryFrom<&mut PacketBuffer> for Header {
    type Error = Error;

    fn try_from(buffer: &mut PacketBuffer) -> Result<Self> {
        if buffer.pos() != 0 {
            return Err(Error::PacketBufferInvalidPosition); //("Packet buffer must be at position 0 before reading Header.");
        }

        // println!("RAW HEADER: {:#?}", &buffer.bytes[0..40]);
        let id = buffer.read_u16()?;

        // First 8 bits
        let byte = buffer.read_u8()?;
        let is_response = byte & 0x80 != 0;
        let _op_code = (byte & 0x74) >> 3;
        let is_authoritative = (byte & 0x04) != 0;
        let is_truncated = (byte & 0x02) != 0;
        let recursion_desired = (byte & 0x01) != 0;

        // Next 8 bits
        let byte = buffer.read_u8()?;
        let recursion_available = (byte & 0x80) != 0;
        let _z = (byte & 0x70) >> 5;
        let response_code = ResultCode::from(byte & 0x0f);

        let question_count = buffer.read_u16()?;
        let answer_count = buffer.read_u16()?;
        let authority_count = buffer.read_u16()?;
        let additional_count = buffer.read_u16()?;

        Ok(Self {
            id,

            is_response,
            _op_code,
            is_authoritative,
            is_truncated,
            recursion_desired,

            recursion_available,
            _z,
            response_code,

            question_count,
            answer_count,
            authority_count,
            additional_count,
        })
    }
}

#[derive(Debug)]
struct Question {
    name: String,
    /// 2 bytes. The record type.
    question_type: QueryType,
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
        let name = buffer.read_qname()?;
        let question_type = QueryType::from(buffer.read_u16()?);
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

#[derive(Debug)]
struct RecordPreamble {
    name: String,
    /// 2 bytes
    record_type: QueryType,
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

#[allow(dead_code)]
#[derive(Debug)]
enum Record {
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
        let name = buffer.read_qname()?;
        let record_type = QueryType::from(buffer.read_u16()?);
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
            QueryType::A => {
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

#[derive(Debug)]
struct DnsPacket {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
}

impl TryFrom<PacketBuffer> for DnsPacket {
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

impl fmt::Display for DnsPacket {
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

fn main() -> Result<()> {
    let mut fd = File::open("data/dns_question.bin").map_err(|_| Error::InvalidInputPath)?;
    let mut buffer = PacketBuffer::new();
    fd.read(&mut buffer.bytes)
        .map_err(|_| Error::FailedReadingFile)?;

    // println!("RAW: {:#?}", &buffer.bytes[0..50]);
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
