use core::fmt;
use std::fmt::Formatter;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub(crate) enum Error {
    PacketBufferInvalidPosition,
    PacketBufferOver512(String),

    /// When reading labels performs too many jumps
    MaxJumpsAttained,

    /// When the input file path cannot be read into a `File`
    InvalidInputPath,

    /// When `read()` on a `std::io::File` fails
    FailedReadingFile,
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
