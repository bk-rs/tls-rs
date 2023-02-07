#[cfg(any(feature = "std_io", feature = "futures_util_io"))]
use std::io::{self, Cursor};

#[cfg(any(feature = "std_io", feature = "futures_util_io"))]
use tls_client_hello_parser::{ClientHelloPayload, ParseOutput, Parser};

#[cfg(feature = "std_io")]
use std_io_peek::Peek;

#[cfg(feature = "futures_util_io")]
use futures_util_io_peek::{AsyncPeek, AsyncPeekExt};

pub struct Detector {
    #[cfg(any(feature = "std_io", feature = "futures_util_io"))]
    parser: Parser,
}

impl Detector {
    #[cfg(any(feature = "std_io", feature = "futures_util_io"))]
    pub fn new() -> Self {
        Self {
            parser: Parser::new(),
        }
    }

    #[cfg(feature = "std_io")]
    pub fn detect<P: Peek>(&mut self, p: &mut P) -> io::Result<ClientHelloPayload> {
        let mut v = vec![0u8; 16 * 1024];
        let mut buf = Cursor::new(vec![]);

        loop {
            match p.peek_sync(&mut v)? {
                0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "")),
                n => {
                    buf.get_mut().extend_from_slice(&v[..n]);
                    match self.parser.parse(&mut buf)? {
                        ParseOutput::Done(chp) => return Ok(chp),
                        ParseOutput::Partial => continue,
                        ParseOutput::Invalid(e) => {
                            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, e))
                        }
                    }
                }
            }
        }
    }

    #[cfg(feature = "futures_util_io")]
    pub async fn detect_async<P: AsyncPeek + Unpin>(
        &mut self,
        p: &mut P,
    ) -> io::Result<ClientHelloPayload> {
        let mut v = vec![0u8; 16 * 1024];
        let mut buf = Cursor::new(vec![]);

        loop {
            match p.peek_async(&mut v).await? {
                0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "")),
                n => {
                    buf.get_mut().extend_from_slice(&v[..n]);
                    match self.parser.parse(&mut buf)? {
                        ParseOutput::Done(chp) => return Ok(chp),
                        ParseOutput::Partial => continue,
                        ParseOutput::Invalid(e) => {
                            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, e))
                        }
                    }
                }
            }
        }
    }
}
