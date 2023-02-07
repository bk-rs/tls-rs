use std::io::Error as IoError;
#[cfg(any(feature = "std_io", feature = "futures_util_io"))]
use std::io::{Cursor, ErrorKind as IoErrorKind};

#[cfg(any(feature = "std_io", feature = "futures_util_io"))]
use tls_client_hello_parser::ClientHelloPayload;
use tls_client_hello_parser::{ParseError, Parser};

#[cfg(feature = "std_io")]
use std_io_peek::Peek;

#[cfg(feature = "futures_util_io")]
use futures_util_io_peek::{AsyncPeek, AsyncPeekExt};

//
pub struct Detector {
    #[allow(dead_code)]
    parser: Parser,
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector {
    pub fn new() -> Self {
        Self {
            parser: Parser::new(),
        }
    }

    #[cfg(feature = "std_io")]
    pub fn detect<P: Peek>(&mut self, p: &mut P) -> Result<ClientHelloPayload, DetectError> {
        let mut v = vec![0u8; 16 * 1024];
        let mut buf = Cursor::new(vec![]);

        loop {
            match p.peek_sync(&mut v).map_err(DetectError::IoError)? {
                0 => {
                    return Err(DetectError::IoError(IoError::new(
                        IoErrorKind::UnexpectedEof,
                        "",
                    )))
                }
                n => {
                    buf.get_mut().extend_from_slice(&v[..n]);
                    match self
                        .parser
                        .parse(&mut buf)
                        .map_err(DetectError::ParseError)?
                    {
                        Some(chp) => return Ok(chp),
                        None => continue,
                    }
                }
            }
        }
    }

    #[cfg(feature = "futures_util_io")]
    pub async fn detect_async<P: AsyncPeek + Unpin>(
        &mut self,
        p: &mut P,
    ) -> Result<ClientHelloPayload, DetectError> {
        let mut v = vec![0u8; 16 * 1024];
        let mut buf = Cursor::new(vec![]);

        loop {
            match p.peek_async(&mut v).await.map_err(DetectError::IoError)? {
                0 => {
                    return Err(DetectError::IoError(IoError::new(
                        IoErrorKind::UnexpectedEof,
                        "",
                    )))
                }
                n => {
                    buf.get_mut().extend_from_slice(&v[..n]);
                    match self
                        .parser
                        .parse(&mut buf)
                        .map_err(DetectError::ParseError)?
                    {
                        Some(chp) => return Ok(chp),
                        None => continue,
                    }
                }
            }
        }
    }
}

//
#[derive(Debug)]
pub enum DetectError {
    IoError(IoError),
    ParseError(ParseError),
}
impl core::fmt::Display for DetectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DetectError {}
