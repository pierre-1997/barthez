use core::fmt;
use std::fmt::Formatter;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    PacketBufferInvalidPosition,
    PacketBufferOver512(String),

    /// When reading labels performs too many jumps
    MaxJumpsAttained,

    /// When the input file path cannot be read into a `File`
    InvalidInputPath,

    /// When `read()` on a `std::io::File` fails
    FailedReadingFile,
    // Packet write error
    // FailedWritingBuffer(String),
    LabelLengthOver63,

    UDPBindFailed,
    UDPSendFailed,
    UDPRecvFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::PacketBufferOver512(s) => writeln!(f, "Buffer overflow: {s}")?,
            _ => writeln!(f, "Error")?,
        }

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum ResultCode {
    #[default]
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
}

impl From<u8> for ResultCode {
    fn from(value: u8) -> Self {
        match value {
            // 0 => ResultCode::NOERROR,
            1 => ResultCode::FormErr,
            2 => ResultCode::ServFail,
            3 => ResultCode::NXDomain,
            4 => ResultCode::NotImp,
            5 => ResultCode::Refused,
            _ => ResultCode::NoError,
        }
    }
}

impl fmt::Display for ResultCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ResultCode::NoError => write!(f, "NOERROR"),
            ResultCode::FormErr => write!(f, "FORMERR"),
            ResultCode::ServFail => write!(f, "SERVFAIL"),
            ResultCode::NXDomain => write!(f, "NXDOMAIN"),
            ResultCode::NotImp => write!(f, "NOTIMP"),
            ResultCode::Refused => write!(f, "REFUSED"),
        }
    }
}
